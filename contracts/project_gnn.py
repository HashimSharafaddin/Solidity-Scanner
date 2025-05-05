import torch
import numpy as np
import re
import os
import subprocess
from evm_cfg_builder.cfg import CFG
from gensim.models import Word2Vec
from nltk.tokenize import word_tokenize
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader
from solcx import compile_source, install_solc, set_solc_version, get_installable_solc_versions, \
    get_installed_solc_versions

from contracts.GraphNN import GNN

# Load models
# modelWord2Vec = Word2Vec.load("./venv/models/word2vec_opcode_16.bin")
from project import settings

modelWord2Vec = Word2Vec.load("contracts/models/word2vec_opcode_16.bin")
badrandomness_check = GNN(hidden_channels=64)
reentrancy_check = GNN(hidden_channels=64)
badrandomness_check.load_state_dict(torch.load("contracts/models/gnn_badrandom_modelf.pth"))
# badrandomness_check.load_state_dict(torch.load("./venv/models/gnn_badrandom_modelf.pth"))
# reentrancy_check.load_state_dict(torch.load("./venv/models/gnn_reentrancy_model3.pt"))
# reentrancy_check.load_state_dict(torch.load("contracts/models/gnn_reentrancy_model33.pt"))
if not torch.cuda.is_available():
    reentrancy_check.load_state_dict(
        torch.load("contracts/models/gnn_reentrancy_model33.pt", map_location=torch.device('cpu')))
else:
    reentrancy_check.load_state_dict(torch.load("contracts/models/gnn_reentrancy_model33.pt"))
badrandomness_check.eval()
reentrancy_check.eval()


def map_opcode_to_embedding(opcode_sequence):
    tokens = word_tokenize(opcode_sequence)
    opcode_sequence = [token.upper() for token in tokens if token.isalnum()]
    embedding_sequence = [modelWord2Vec.wv[token] for token in opcode_sequence if token in modelWord2Vec.wv]
    if not embedding_sequence:
        embedding_sequence = [np.zeros(modelWord2Vec.vector_size)]
    avg = np.mean(embedding_sequence, axis=0)
    max_ = np.max(embedding_sequence, axis=0)
    sum_ = np.sum(embedding_sequence, axis=0)
    final_embedding = np.concatenate([avg, max_, sum_])
    norm = np.linalg.norm(final_embedding)
    if norm > 0:
        final_embedding = final_embedding / norm
    return np.resize(final_embedding, (48))


def process_block(block):
    opcodes = [info[0] for info in block['info']]
    return map_opcode_to_embedding('\n'.join(opcodes))


def process_bytecode(bytecode):
    cfg = CFG(bytecode)
    sorted_data = {
        str(block): {
            'pos': block.start.pc,
            'info': [(instr.mnemonic, instr.description) for instr in block.instructions],
            'out': [str(out_block) for out_block in block.all_outgoing_basic_blocks],
        }
        for block in cfg.basic_blocks
    }
    keys = sorted(sorted_data.keys(), key=lambda k: sorted_data[k]['pos'])
    graph_embedding = [process_block(sorted_data[k]) for k in keys]
    x = torch.tensor(np.vstack(graph_embedding), dtype=torch.float)
    pos_to_idx = {sorted_data[k]['pos']: idx for idx, k in enumerate(keys)}
    edge_index = torch.tensor([
        [pos_to_idx[sorted_data[k]['pos']] for k in keys for _ in sorted_data[k]['out']],
        [pos_to_idx[sorted_data[out]['pos']] for k in keys for out in sorted_data[k]['out']]
    ], dtype=torch.long)
    return Data(x=x, edge_index=edge_index)


def scan_with_gnn(bytecode):
    graph = process_bytecode(bytecode)
    loader = DataLoader([graph], batch_size=1)
    result = {"Reentrancy": False, "Bad Randomness": False}
    for data in loader:
        with torch.no_grad():
            re_pred = reentrancy_check(data.x, data.edge_index, data.batch)
            br_pred = badrandomness_check(data.x, data.edge_index, data.batch)
            if torch.softmax(re_pred, dim=1)[0][0] > 0.5:
                result["Reentrancy"] = True
            if torch.softmax(br_pred, dim=1)[0][1] > 0.65:
                result["Bad Randomness"] = True
    return result


def scan_with_mythril(bytecode):
    try:
        result = subprocess.run([
            "docker", "run", "--rm", "-v", f"{os.getcwd()}:/tmp",
            "mythril/myth", "analyze", "--code", bytecode
        ], capture_output=True, text=True)
        output = result.stdout.lower()
        return {
            "Reentrancy": "reentrancy" in output,
            "Bad Randomness": any(x in output for x in ["timestamp", "block.number"])
        }
    except Exception as e:
        print(f"Mythril Docker Error: {e}")
        return {"Reentrancy": False, "Bad Randomness": False}


def scan_with_manticore(bytecode):
    try:
        with open("contract.hex", "w") as f:
            f.write(bytecode)
        result = subprocess.run([
            "docker", "run", "--rm", "-v", f"{os.getcwd()}:/workspace",
            "trailofbits/manticore", "manticore", "/workspace/contract.hex"
        ], capture_output=True, text=True)
        output = result.stdout.lower()
        return {
            "Reentrancy": "reentrancy" in output,
            "Bad Randomness": any(x in output for x in ["timestamp", "block.number"])
        }
    except Exception as e:
        print(f"Manticore Docker Error: {e}")
        return {"Reentrancy": False, "Bad Randomness": False}


def extract_solidity_version(source):
    match = re.search(r'pragma solidity\s+([^;]+);', source)
    if match:
        versions = re.findall(r'\d+\.\d+\.\d+', match.group(1))
        return versions[0] if versions else None
    return None


def compile_solidity(source_code):
    version = extract_solidity_version(source_code)
    installable = [str(v) for v in get_installable_solc_versions()]
    installed = [str(v) for v in get_installed_solc_versions()]
    prefix = version[:3] if version else '0.8'
    compat = [v for v in installable if v.startswith(prefix)]
    version_to_use = compat[0] if compat else '0.8.0'
    if version_to_use not in installed:
        install_solc(version_to_use)
    set_solc_version(version_to_use)
    compiled = compile_source(source_code, output_values=['bin'])
    _, contract = next(iter(compiled.items()))
    return contract['bin']


def scan_file(mode, file_path, contract_content):
    message = ''

    file_name = None
    contract_content_text = None
    vulnerability_found = ''
    vulnerability_count = 0
    report = ''
    detections = []
    status = 2
    stop_detection = False

    if mode == 1:
        if contract_content is None:
            message = "Paste the contract's raw bytecode "
            return None, message
        else:
            contract_content_text = contract_content
            bytecode = compile_solidity(contract_content_text)
            # bytecode = compile_solidity_to_bytecode(contract_content)
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
            bytecode = compile_solidity(source_code)
            # print(bytecode)
    else:
        message = "Paste the contract's raw bytecode: "
        return None, message

    try:
        mythril_result = scan_with_mythril(bytecode)
        print("Mythril Result:", mythril_result)
        if mythril_result["Reentrancy"] and mythril_result["Bad Randomness"]:
            status = 1
            vulnerability_count = 2
            detections.append({
                "type": "Reentrancy",
                "class_name": "Reentrancy",
                "detection_tool": 'Mythril',
                "desc": " Reentrancy is when a contract makes an external call before updating state. This may lead to repeated calls and fund drainage."
            })
            detections.append({
                "type": "Bad_Randomness",
                "class_name": "Bad Randomness",
                "detection_tool": 'Mythril',
                "desc":"Bad Randomness happens when contracts use predictable sources (e.g., block.timestamp) to generate random values. Attackers can exploit this."
            })
            print("Both vulnerabilities found with Mythril. Skipping other checks.")
            report = "Both vulnerabilities found with Mythril. Skipping other checks."
            stop_detection = True
            # exit(0)


        manticore_result = scan_with_manticore(bytecode)
        print("Manticore Result:", manticore_result)
        if manticore_result["Reentrancy"] and manticore_result["Bad Randomness"]:
            status = 1
            vulnerability_count = 2
            detections.append({
                "type": "Reentrancy",
                "class_name": "Reentrancy",
                "detection_tool": 'Manticore',
                "desc": " Reentrancy is when a contract makes an external call before updating state. This may lead to repeated calls and fund drainage."
            })
            detections.append({
                "type": "Bad_Randomness",
                "class_name": "Bad Randomness",
                "detection_tool": 'Manticore',
                "desc":"Bad Randomness happens when contracts use predictable sources (e.g., block.timestamp) to generate random values. Attackers can exploit this."
            })

            print("Both vulnerabilities found with Manticore. Skipping GNN check.")
            report =  "Both vulnerabilities found with Manticore."
            stop_detection = True
            exit(0)

        gnn_result = scan_with_gnn(bytecode)
        print("GNN Model Result:", gnn_result)

        print("\n=== Summary ===")
        if not stop_detection and any([mythril_result["Reentrancy"], manticore_result["Reentrancy"], gnn_result["Reentrancy"]]):
            tool_results = {
                "Mythril": mythril_result["Reentrancy"],
                "Manticore": manticore_result["Reentrancy"],
                "GNN": gnn_result["Reentrancy"]
            }
            detectors = [tool for tool, result in tool_results.items() if result]
            status = 1
            vulnerability_count = 1
            report = "\n Reentrancy is found with " + ", ".join(detectors)

            detections.append({
                "type": "Reentrancy",
                "class_name": "Reentrancy",
                "detection_tool": ", ".join(detectors),
                "desc": " Reentrancy is when a contract makes an external call before updating state. This may lead to repeated calls and fund drainage."

            })
            print("- Reentrancy vulnerability detected.")

        if not stop_detection and any([mythril_result["Bad Randomness"], manticore_result["Bad Randomness"], gnn_result["Bad Randomness"]]):
            tool_results = {
                "Mythril": mythril_result["Bad Randomness"],
                "Manticore": manticore_result["Bad Randomness"],
                "GNN": gnn_result["Bad Randomness"]
            }
            detectors = [tool for tool, result in tool_results.items() if result]

            status = 1
            vulnerability_count = vulnerability_count + 1
            detections.append({
                "type": "Bad_Randomness",
                "class_name": "Bad Randomness",
                "detection_tool": ", ".join(detectors),
                "desc":"Bad Randomness happens when contracts use predictable sources (e.g., block.timestamp) to generate random values. Attackers can exploit this."
            })
            report = report + "\n Bad Randomness is detected with " + ", ".join(detectors)
            print("- Bad Randomness vulnerability detected.")

        if not any([*mythril_result.values(), *manticore_result.values(), *gnn_result.values()]):
            status = 0
            # print("No vulnerabilities detected by any tool.")
            report = "No vulnerabilities detected by any tool."

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


def get_severity(score):
    if 60 < score < 70:
        return 'Low'
    elif 70 <= score < 80:
        return 'Medium'
    elif 80 <= score < 90:
        return 'Critical'
    elif 90 <= score < 100:
        return 'High'
    else:
        return 'Normal'


def get_severity_color(score):
    if 60 < score < 70:
        return '#68FF88'
    elif 70 <= score < 80:
        return '#FFFB87'
    elif 80 <= score < 90:
        return '#530900'
    elif 90 <= score < 100:
        return '#FF2211'
    else:
        return '#68FF88'





# # Entry point
# if __name__ == "__main__":
#     print("=== Smart Contract Vulnerability Scanner ===")
#     choice = input("Input type (1 = Solidity Source Code, 2 = EVM Bytecode): ").strip()
#     final_bytecode = ""
#
#     if choice == "1":
#         path = input("Enter path to Solidity file: ").strip()
#         if os.path.exists(path):
#             with open(path, "r") as f:
#                 source = f.read()
#             final_bytecode = compile_solidity(source)
#         else:
#             print("File not found.")
#             exit(1)
#     elif choice == "2":
#         final_bytecode = input("Paste EVM bytecode (without 0x): ").strip()
#         if not final_bytecode:
#             print("No bytecode provided.")
#             exit(1)
#     else:
#         print("Invalid choice.")
#         exit(1)
#
#     print("\nRunning Mythril analysis...")
#     mythril_result = scan_with_mythril(final_bytecode)
#     print("Mythril Result:", mythril_result)
#
#     if mythril_result["Reentrancy"] and mythril_result["Bad Randomness"]:
#         print("Both vulnerabilities found with Mythril. Skipping other checks.")
#         exit(0)
#
#     print("\nRunning Manticore analysis...")
#     manticore_result = scan_with_manticore(final_bytecode)
#     print("Manticore Result:", manticore_result)
#
#     if manticore_result["Reentrancy"] and manticore_result["Bad Randomness"]:
#         print("Both vulnerabilities found with Manticore. Skipping GNN check.")
#         exit(0)
#
#     print("\nRunning GNN model analysis...")
#     gnn_result = scan_with_gnn(final_bytecode)
#     print("GNN Model Result:", gnn_result)
#
#     print("\n=== Summary ===")
#     if any([mythril_result["Reentrancy"], manticore_result["Reentrancy"], gnn_result["Reentrancy"]]):
#         print("- Reentrancy vulnerability detected.")
#
#     if any([mythril_result["Bad Randomness"], manticore_result["Bad Randomness"], gnn_result["Bad Randomness"]]):
#         print("- Bad Randomness vulnerability detected.")
#
#     if not any([*mythril_result.values(), *manticore_result.values(), *gnn_result.values()]):
#         print("No vulnerabilities detected by any tool.")

