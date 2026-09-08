"""OCI service collectors. Every collector calls only officially documented
read (``get_*``/``list_*``) OCI SDK operations through
:mod:`oci_drata.pagination`, and returns raw SDK model objects in memory --
allowlisting into :mod:`oci_drata.models` source facts happens in
:mod:`oci_drata.transform.normalize`, not here.
"""
