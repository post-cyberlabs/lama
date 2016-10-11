TODO list
=========

Architecture
------------

- If detected with AV -> don't analyze (Faster but without Indicator)
- Improve analysis cycle

Analysis
--------

- Check if already analyzed
- Timeout
- Limit cycle (A->B->A->B->...)
- Limit depth (A1->A2->A3->A4->...)
- Improve Web part (with ajax, loading bar, style, ...)
- Improve type mime (use TrID, ...)

Module
------

- Multiple instance of remote platform (with one module -> Cuckoo1, Cuckoo2, Cuckoo3, ...)
- Add module


Bugs
----

- RabbitMQ lost connection
- find and kill all bugs ^^
