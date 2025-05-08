from django import template
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.template import loader
from apps.home.forms import ScanFileForm
import os
from django.shortcuts import render, redirect
from django.conf import settings

from contracts.project_gnn import scan_file


def pages(request):
    context = {}
    try:

        load_template = request.path.split('/')[-1]
        print(load_template)

        return redirect('/')


    except template.TemplateDoesNotExist:

        html_template = loader.get_template('home/page-404.html')
        return HttpResponse(html_template.render(context, request))

    except:
        html_template = loader.get_template('home/page-500.html')
        return HttpResponse(html_template.render(context, request))


def scan_page(request):
    context = {'segment': 'index'}
    scan_result = None

    if request.method == 'POST':
        scan_result, msg = handle_scan_logic(request)
        form = ScanFileForm()
        context.update({
            'form': form,
            'scan_result': scan_result,
            'scan_error': msg,
        })
    else:
        form = ScanFileForm()  # Create an instance of the form
        context.update({
            'form': form,
            'scan_result': None,
            'scan_error': None,
        })

    print(scan_result)
    return render(request, 'home/scan.html', context)


def handle_scan_logic(request):
    scan_result = None
    msg = None
    form = ScanFileForm(request.POST, request.FILES)
    if form.is_valid():
        # File upload
        if form.cleaned_data['contract_file']:
            solidity_file = form.cleaned_data['contract_file']
            filename_base = solidity_file.name.replace('.sol', '')
            filename = f"{filename_base}.sol"
            output_path = os.path.join(settings.MEDIA_ROOT, filename)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'wb') as f:
                for chunk in solidity_file.chunks():
                    f.write(chunk)

            # Scan uploaded file
            res, err = scan_file(2, output_path, None)
            if res is None:
                scan_result = err
            else:
                scan_result = res

        # Text input
        elif form.cleaned_data['contract_input']:
            contract_code = form.cleaned_data['contract_input']
            res, err = scan_file(1, '', contract_code)
            if res is None:
                scan_result = err
            else:
                scan_result = res

        else:
            msg = 'No contract content provided'
            scan_result = None
    else:
        msg = form.non_field_errors()  # Errors from `clean()` method
        scan_result = None
    # print(scan_result)
    return scan_result, msg


