.. _variorum_sampler:

=======================
variorum_sampler
=======================

--------------------------------------
Man page for the LDMS Variorum plugin
--------------------------------------

:Date:   27 Jun 2022
:Manual section: 7
:Manual group: LDMS sampler

SYNOPSIS
========

| Within ldmsd_controller or a configuration file:
| config name=variorum_sampler [common attributes]

DESCRIPTION
===========

With LDMS (Lightweight Distributed Metric Service), plugins for the
ldmsd (ldms daemon) are configured via ldmsd_controller or a
configuration file. The variorum_sampler plugin provides power data
using the JSON API in Variorum, a vendor-neutral library that provides
access to low-level hardware knobs. The sampler, when configured,
automatically detects the number of sockets on the host machine and then
provides, for each socket, an LDMS record containing power data. For
each socket, the values provided are: node power consumption in Watts
(identical across sockets); socket ID number; CPU power consumption in
Watts; GPU power consumption in Watts (aggregated across all GPUs on the
socket, and reported as -1 on unsupported platforms); and memory power
consumption in Watts.

The variorum sampler depends on Variorum 0.8.0 or higher and Jansson.
The sampler cannot be built without these libraries. If either library
is installed in a non-standard location, paths to the respective install
directories should be provided to Autoconf using the
--with-libjansson-prefix and/or --with-libvariorum-prefix flag.

CONFIGURATION ATTRIBUTE SYNTAX
==============================

The variorum sampler plugin uses the sampler_base base class. This man
page covers only the configuration attributes, or those with default
values, specific to the this plugin; see :ref:`ldms_sampler_base(7) <ldms_sampler_base>` for the
attributes of the base class.

**config**
   | name=<plugin_name> exclude_ports=<devs>
   | configuration line

   name=<plugin_name>
      |
      | This MUST be variorum_sampler.

   schema=<schema>
      |
      | Optional schema name. It is intended that the same sampler on
        different nodes with different metrics have a different schema.
        If not specified, will default to \`variorum_sampler`.

BUGS
====

No known bugs; however, if Variorum cannot access the hardware knobs,
the sampler will be unable to access any data. This will result in an
error being printed to the log file: "variorum_sampler: unable to obtain
JSON object data". This error can be resolved by ensuring that hardware
knob access is enabled using the requirements here:
https://variorum.readthedocs.io/en/latest/HWArchitectures.html

EXAMPLES
========

Within ldmsd_controller or a configuration file:

::

   load name=variorum_sampler
   config name=variorum_sampler producer=vm1_1 instance=vm1_1/variorum_sampler
   start name=variorum_sampler interval=1000000

AUTHORS
=======

Jessica Hannebert <j_hannebert@coloradocollege.edu> (Colorado College,
internship at Lawrence Livermore National Laboratory). Tapasya Patki
<patki1@llnl.gov> (Lawrence Livermore National Laboratory). Kathleen
Shoga <shoga1@llnl.gov> (Lawrence Livermore National Laboratory).
Stephanie Brink <brink2@llnl.gov> (Lawrence Livermore National
Laboratory). Barry Rountree <rountree4@llnl.gov> (Lawrence Livermore
National Laboratory).

SEE ALSO
========

:ref:`ldmsd(8) <ldmsd>`, :ref:`ldms_quickstart(7) <ldms_quickstart>`, :ref:`ldmsd_controller(8) <ldmsd_controller>`, :ref:`ldms_sampler_base(7) <ldms_sampler_base>`
