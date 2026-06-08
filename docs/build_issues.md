# Build Issues and Workarounds

## CoRE4INET Compatibility Issues

### Expected Versions

* OMNeT++ 6.0.2
* INET 3.8.x

### Current Environment

* OMNeT++ 6.4.0
* INET 4.6

### Observed Problems

1. `opp_makemake` option incompatibility (`--no-deep-includes` not recognized).
2. IPv4 feature dependency mismatch during build.
3. EtherFrame API changes between INET 3.x and INET 4.x.
4. Ieee802Ctrl API changes causing message compilation failures.
5. Multiple message definition incompatibilities during CoRE4INET compilation.

### Workarounds

* Disabled the IPoRE feature in CoRE4INET.
* Modified Makefile options to remove unsupported arguments.
* Used CoRE4INET only for studying IEEE 802.1Qci PSFP implementation.
* Selected INET 4.6 as the primary simulation platform.

### Final Decision

* Primary simulator: INET 4.6
* Reference implementation: CoRE4INET IEEE 802.1Qci modules
CoRE4INET incompatibility issues you encountered.
