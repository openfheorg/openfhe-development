# Core Library Implementation

```mermaid
flowchart BT
    A[Math<br> - Provides base math operations </br> - Supports various math backends] --> B[Lattice <br> - Represent polynomial rings </br> - support operations over polynomial rings. </br> - calls math layer for lower-level math ops];
    B[Lattice <br> - Represent polynomial rings </br> - support operations over polynomial rings. </br> - calls math layer for lower-level math ops] --> C[Core Layer];
```

Contains the underlying primitives that are used in both `pke` and `binfhe`.

## [Lattice](lattice)

- Contains files that support lattice/polynomial-layer operations in OpenFHE. This layer is used to represent polynomial rings and support operations over those rings. 

- As can be seen above, this is the "middle" layer between higher-level lattice cryptography elements, and the lower level math operations.


## [Math](math)

Contains various files describing the mathematical functionality supported in OpenFHE. For example:

- modular arithmeric
- sampling functions

In addition, the hardware abstraction layer (HAL) is defined here.


## [Utils](utils)

Contains various utilities:

- debugging utilities
- memory management utilities
- parallel operations
- serialization
