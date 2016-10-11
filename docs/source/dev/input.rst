Input
=====

To create your input module, you need to call the Input class with paths to file and/or urls and run analyze method.

Like this ::

  inp = Input(paths, urls)
  analysis_id = inp.analyze()

If you want to analyze an extracted file from the current malware object ::

  extract_file = malware_object.add_extract_malware_path(module_name, file_path, file_name)
  Input.analyse_malware(extract_file)

With :

- malware_object : The current malware object
- module_name : The name of the module
- file_path : The extracted file path
- file_name : The extracted file name
