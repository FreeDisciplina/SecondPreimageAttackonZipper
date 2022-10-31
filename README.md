# Second-Preimage Attack on Zipper Hash #

This program is an implementation of the second preimage attack on Zipper hash, which is devised in [\[1\]](http://eprint.iacr.org/2017/534).


## Dependency and Running Environment ##

In this implementation, AES-128 and SMS4-128 are used to generate the two independent compression functions (message blocks are act as the key of the encrypt cipher, and the hash states are the input and output of the encrypt cipher). We directly use implementations of AES and SMS4 included in IPPCP (Cryptography for Intel Intergrated Performance Primitives) in IPP (Intel Integrated Performance Primitives). Thus, one may need to install IPP and IPPCP to compile and run this experiment.

This program is tested on the following platform:
Windows 10 + VS 2015 + Intel C/C++ compiler


## Results ##

In this simulation, we run 100 times of cycle search algorithm to detect the roots of the largest trees. When `n < 64`, considering that `100 > 2^6`, the number of calls of cycle search algorithm is not relatively negligible. Besides, when `n < 64`, `log(n)` is not relatively negligible (`n/16 < log(n)` for `n < 64`). Thus, the simulation results show that the most costly phases are the phase of detecting root of the largest tree and the phase of building the simultaneous expandable message. That is not conflict with the estimated complexity of the attack in the paper. We believe that, when `n >= 64`, the number of funciton calls of precomputation phase and that of the hitting two root simultaneously phase will be the utmost among all phases as expected. The sumulation results show that number of function calls in precomputation phase and that of the hitting two root simultaneously phase is as same as expected.

Examples of the simulation results are shown in the following (These are results of 10 times simulation):

- [n16_attack_record.txt](https://github.com/FreeDisciplina/SecondPreimageAttackonZipper/blob/main/Results/n16_attack_record.txt)

- [n24_attack_record.txt](https://github.com/FreeDisciplina/SecondPreimageAttackonZipper/blob/main/Results/n24_attack_record.txt)

- [n32_attack_record.txt](https://github.com/FreeDisciplina/SecondPreimageAttackonZipper/blob/main/Results/n32_attack_record.txt)

## References ##

[1] Zhenzhen Bao, Lei Wang, Jian Guo, Dawu Gu: Functional Graph Revisited: Updates on (Second) Preimage Attacks on Hash Combiners. CRYPTO 2017. http://eprint.iacr.org/2017/534
