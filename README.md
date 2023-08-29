# jupyter_dtools
A module to help interaction with Jupyter Notebooks and Domain Tools API

------
This is a python module that helps to connect Jupyter Notebooks to various datasets. 
It's based on (and requires) https://github.com/JohnOmernik/jupyter_integration_base 



## Initialization 
----

### Example Inits

#### Embedded mode using qgrid
```
from dtools_core import Dtools
ipy = get_ipython()
Dtools = Dtools(ipy, debug=False, pd_display_grid="qgrid")
ipy.register_magics(Dtools)
```

