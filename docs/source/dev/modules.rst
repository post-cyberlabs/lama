Synchrone and Asynchrone modules
================================


Module need to extends the Module or SyncModule class and overrides 3 (or 2) methods :

- analyze(self) : method to run the analysis
- check_elem(self) : method to check if the analysis is finish. (Except for SyncModule)
- parse_result(self) : method to parse results


The module need to override the global variable "_module_name", it's use by the Web interface.

On __init__() function, you need to call ``super().__init__("<Module name>", malware, local_path)``
Parameters are the name of module, the malware object and the path to malware file.

Example of module

.. literalinclude:: ../code/module_example.py
    :language: python
    :emphasize-lines: 0
