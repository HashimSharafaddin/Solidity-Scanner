import os
import torch
import numpy as np
import re
from gensim.models import Word2Vec
from nltk.tokenize import word_tokenize
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader
from solcx import compile_source, install_solc, set_solc_version

from contracts.GraphNN import GNN
from evm_cfg_builder.cfg import CFG

# === Load Pre-trained Models ===
# from contracts.serializer import SaveReportSerializer
from project import settings

modelWord2Vec = Word2Vec.load("contracts/models/word2vec_opcode_16.bin")

badrandomness_check = GNN(hidden_channels=64)
reentrancy_check = GNN(hidden_channels=64)

#  Specify the device (CPU) when loading the models
badrandomness_check.load_state_dict(torch.load("contracts/models/gnn_badrandom_modelf.pth", map_location=torch.device('cpu')))
reentrancy_check.load_state_dict(torch.load("contracts/models/gnn_reentrancy_model33.pt", map_location=torch.device('cpu')))

badrandomness_check.eval()
reentrancy_check.eval()


# === Embedding and Graph Processing ===
def map_opcode_to_embedding(opcode_sequence):
    tokens = word_tokenize(opcode_sequence)
    opcode_sequence = [token.upper() for token in tokens if token.isalnum()]
    embedding_sequence = [modelWord2Vec.wv[token] for token in opcode_sequence if token in modelWord2Vec.wv]
    if not embedding_sequence:
        embedding_sequence = [np.zeros(modelWord2Vec.vector_size)]
    average_embedding = np.mean(embedding_sequence, axis=0)
    max_embedding = np.max(embedding_sequence, axis=0)
    sum_embedding = np.sum(embedding_sequence, axis=0)
    final_embedding = np.concatenate([average_embedding, max_embedding, sum_embedding])
    norm = np.linalg.norm(final_embedding)
    if norm > 0:
        final_embedding = final_embedding / norm
    final_embedding = np.resize(final_embedding, (48))
    return final_embedding


def process_block(block):
    block_opcode = [info[0] for info in block['info']]
    block_embedding = map_opcode_to_embedding('\n'.join(block_opcode))
    return block_embedding


def process_bytecode(bytecode):
    cfg = CFG(bytecode)
    sorted_data_mapping = {
        str(block): {
            'pos': block.start.pc,
            'info': [(instr.mnemonic, instr.description) for instr in block.instructions],
            'out': [str(out_block) for out_block in block.all_outgoing_basic_blocks],
        }
        for block in cfg.basic_blocks
    }
    sorted_keys = sorted(sorted_data_mapping.keys(), key=lambda key: sorted_data_mapping[key]['pos'])
    graph_embedding = [process_block(sorted_data_mapping[key]) for key in sorted_keys]
    x = torch.tensor(np.vstack(graph_embedding), dtype=torch.float)

    pos_to_idx = {sorted_data_mapping[key]['pos']: idx for idx, key in enumerate(sorted_keys)}
    edge_index = torch.tensor([
        [pos_to_idx[sorted_data_mapping[key]['pos']] for key in sorted_keys for _ in sorted_data_mapping[key]['out']],
        [pos_to_idx[sorted_data_mapping[out_block]['pos']] for key in sorted_keys for out_block in
         sorted_data_mapping[key]['out']]
    ], dtype=torch.long)

    return Data(x=x, edge_index=edge_index)


def scan_bytecode(bytecode):
    graph = process_bytecode(bytecode)
    data_loader = DataLoader([graph], batch_size=1, shuffle=False)
    final_predictions = []
    detections = []

    for data in data_loader:
        with torch.no_grad():
            badrandom_preds = badrandomness_check(data.x, data.edge_index, data.batch)
            reentrancy_preds = reentrancy_check(data.x, data.edge_index, data.batch)

            badrandom_probs = torch.softmax(badrandom_preds, dim=1)
            reentrancy_probs = torch.softmax(reentrancy_preds, dim=1)


            if badrandom_probs[0][1] > 0.65:
                conf = round(((badrandom_probs[0][1]).item()*100), 2)
                severity = get_severity(conf)
                severity_color = get_severity_color(conf)
                detections.append({"type": "Bad_Randomness",
                                   "class_name": "Bad Randomness",
                                   "severity": severity,
                                   "severity_color": severity_color,
                                   "confidence":  conf,
                                   "desc" : " Reentrancy is when a contract makes an external call before updating state. This may lead to repeated calls and fund drainage."})
                final_predictions.append("Bad Randomness")

            if reentrancy_probs[0][0] > 0.5:
                conf = round(((reentrancy_probs[0][0]).item()*100), 2)
                severity = get_severity(conf)
                severity_color = get_severity_color(conf)
                detections.append({"type": "Reentrancy",
                                   "class_name": "Reentrancy",
                                   "severity": severity,
                                   "severity_color": severity_color,
                                   "confidence":  conf,
                                   "desc" : "\n - Bad Randomness happens when contracts use predictable sources (e.g., block.timestamp) to generate random values. Attackers can exploit this."
                                   })
                final_predictions.append("Reentrancy")

    return detections
    # return final_predictions


# === Compilation Helpers ===
def extract_solidity_version(source):
    match = re.search(r'pragma solidity\s+([^;]+);', source)
    if match:
        version_spec = match.group(1).strip()
        version_numbers = re.findall(r'\d+\.\d+\.\d+', version_spec)
        if version_numbers:
            return version_numbers[0]
    return None


def compile_solidity_to_bytecode(source_code):
    version = extract_solidity_version(source_code)
    version = version if version else "0.8.0"
    install_solc(version)
    set_solc_version(version)
    compiled_sol = compile_source(source_code, output_values=['abi', 'bin'])
    contract_id, contract_interface = next(iter(compiled_sol.items()))
    return contract_interface['bin']


def scan_file(mode, file_path, contract_content):

    message = ''

    file_name = None
    contract_content_text = None
    vulnerability_found = ''
    vulnerability_count = 0
    report = ''
    detections = []

    if mode == 1:
        if contract_content is None:
            message = "Paste the contract's raw bytecode "
            return None, message
        else:
            contract_content_text = contract_content
            bytecode = compile_solidity_to_bytecode(contract_content)
            print(contract_content)
    elif mode == 2:
        if file_path is None:
            message = "Upload the contract's .sol file "
            return None, message
        else:
            file_name = file_path
            path = file_path.strip()
            with open(path, 'r') as f:
                source_code = f.read()
            contract_content_text = source_code
            print(source_code)
            bytecode = compile_solidity_to_bytecode(source_code)
            print(bytecode)
    else:
        message = "Paste the contract's raw bytecode: "
        return None, message

    try:
        results = scan_bytecode(bytecode)
        print(f" - {results}")
        if results:
            status = 1
            for label in results:
                detections.append(label)
                if vulnerability_found == '':
                    vulnerability_found = label['class_name']
                else:
                    vulnerability_found = f"{vulnerability_found} - {label['class_name']}"
                print(f" - {label}")
            vulnerability_count = len(results)

            if "Reentrancy" in results:
                txt = "\n - Reentrancy is when a contract makes an external call before updating state. This may lead to repeated calls and fund drainage."
                report = f"{report} \n  {txt}"
                print(txt)

            if "Bad Randomness" in results:
                txt = "\n - Bad Randomness happens when contracts use predictable sources (e.g., block.timestamp) to generate random values. Attackers can exploit this."
                report = f"{report} \n  {txt}"
                print(txt)

        else:
            status = 2
            report = "🎉 No vulnerabilities detected."

        content = {
            "contract_file_name": file_name,
            "contract_content_text": contract_content_text,
            "vulnerability_count": vulnerability_count,
            "Vulnerability_found": vulnerability_found,
            "report": report,
            "status": status,
            "reportDetections": detections,
            "contract_type": mode,
        }


        delete_file(file_path)
        return None, content

    except Exception as e:
        delete_file(file_path)
        message = f"🚨 Error: {e}"
        print(message)
        return None, message




def delete_file(file_path):
    print('delete_file')
    i_path = os.path.join(settings.MEDIA_ROOT, file_path.lstrip('/'))
    if os.path.exists(i_path):
        try:
            os.remove(i_path)
        except Exception as e:
            print(f"Error deleting file {i_path}: {e}")


# def save_report(myData):
#     print('save_report')
#
#     serializer = SaveReportSerializer(data=myData)
#     try:
#         if serializer.is_valid():
#             try:
#                 obj = serializer.save()
#                 return obj, 'success'
#             except Exception as e:
#                 print(str(e))
#                 return None, str(e)
#         else:
#             print(str(serializer.errors))
#             return None, str(serializer.errors)
#     except Exception as e:
#         print(str(e))
#         return None,  str(e)






# Your Security Score is LOW
#
# The SolidityScan score is calculated based on lines of code and weights assigned to each issue depending on the severity and confidence. To improve your score, view the detailed result and leverage the remediation solutions provided.

# Severity


def get_severity(score):
    if 60 < score < 70:
        return 'Low'
    elif 70 <= score < 80:
        return 'Medium'
    elif 80 <= score < 90:
        return 'Critical'
    elif 90 <= score < 100:
        return 'High'
    else: return 'Normal'


def get_severity_color(score):
    if 60 < score < 70:
        return '#68FF88'
    elif 70 <= score < 80:
        return '#FFFB87'
    elif 80 <= score < 90:
        return '#530900'
    elif 90 <= score < 100:
        return '#FF2211'
    else: return '#68FF88'


#
# # === Main CLI Driver ===
# def main():
#     print("Smart Contract Vulnerability Scanner (Reentrancy & Bad Randomness)")
#     mode = input("Choose mode: [1] Raw Bytecode  [2] Solidity Source File: ").strip()
#
#     if mode == '1':
#         bytecode = input("Paste the contract's raw bytecode: ").strip()
#     elif mode == '2':
#         path = input("Enter path to Solidity (.sol) file: ").strip()
#         with open(path, 'r') as f:
#             source_code = f.read()
#         bytecode = compile_solidity_to_bytecode(source_code)
#     else:
#         print("Invalid option.")
#         return
#
#     try:
#         results = scan_bytecode(bytecode)
#         if results:
#             print("\n🛡️ Vulnerabilities Found:")
#             for label in results:
#                 print(f" - {label}")
#             print(f"\nTotal: {len(results)} vulnerabilities found.")
#
#             if "Reentrancy" in results:
#                 print("\n[INFO] Reentrancy is when a contract makes an external call before updating state. This may lead to repeated calls and fund drainage.")
#             if "Bad Randomness" in results:
#                 print("\n[INFO] Bad Randomness happens when contracts use predictable sources (e.g., block.timestamp) to generate random values. Attackers can exploit this.")
#         else:
#             print("🎉 No vulnerabilities detected.")
#     except Exception as e:
#         print(f"🚨 Error: {e}")
#
# if __name__ == "__main__":
#     main()
