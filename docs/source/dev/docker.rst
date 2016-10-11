Docker modules
==============


Python part
-----------

Docker module extends of SyncModule, you need to override just one methods :

- parse_result(self) : Method to parse results

The module need to override the global variable "_module_name", it's use by the Web interface.

On __init__() function, you need to call ``super().__init__("<Docker Module Name>", malware, local_path, "container_name")``
Parameters are the name of module, the malware object, the path to malware file and the name of the container.
The name of the container is the name of his folder (see next part).


Example of Docker Module

.. literalinclude:: ../code/docker_module_example.py
    :language: python
    :emphasize-lines: 0



Docker part
-----------

On directory ``lama/docker`` you need to create a directory with a Dockerfile and a script.py file.
The directory name must be composed with lowercase char (a-z), underscore (_) and dash (-).
The script.py file will be add on /lama folder.
You can add other file as you want on this directory.

When the container is running, the malware file is added into ``/lama`` directory with the name ``sample``.
You need to read this file for your analysis.
After analysis, the parse_result method collect all output data from stdout and stderr.

If you want, you can store file on ``/lama/out`` directory and get them after.
If you create the file ``/lama/out/test.txt`` on the container, you can get it with ``self._out_tmp_path + "test.txt"`` on the parse_result method to access on this file (the variable _out_tmp_path is linked to /lama/out folder);

After the creation of the container you will have directory/files ::

/lama/script.py
/lama/sample
/lama/out/

For that, on your Dockerfile you need to add the rule ``COPY script.py /lama/script.py`` at the end.
The script.py is the first call by the module, on this file you can call other file or program.

When you've finished your Dockerfile and script, you need to run the ``build_docker.sh`` script on the lama/docker project folder.
If you have errors ... debug it ;)
