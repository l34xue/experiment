In our scheme, compared with the original Zerocash scheme, we add the Register algorithm, the Trace algorithm, and a zero-knowledge proof $\pi_2$ in the Pour algorithm, which is used for checking whether the regulatory policies are satisfied.  We simulate and analyze the overhead of the added algorithms in the proposed scheme.

In the simulation experiments, we test the computational cost of the Trace and Pour algorithms (test.cpp under the miracl directory) in which the [Miracl library](https://github.com/miracl/MIRACL "Multiprecision Integer and Rational Arithmetic Cryptographic Library") is utilized. For $\pi_2$, since the Merkle hash tree (MHT) proof generation is the most time-consuming, we conduct experiments on the MHT proof generation and verification (Main.cpp under the Merkle directory) to test the computational cost, where the [Libsnark library](https://github.com/scipr-lab/libsnark "a C++ library for zkSNARKs") is utilized. For the sigma proof in $\pi_2$, we analyze the computational overhead of different sigma proofs based on the cryptographic operations involved. The results can be found in the performance evaluation subsection. The steps to run the simulation code are as follows:

First, download the experiment repository 

 ```shell
 git clone https://github.com/l34xue/experiment.git
 ```

For the simulation of MHT proof generation and verification, we run the code in the WSL (Windows Subsystem for Linux) on a laptop with Intel(R) Core(TM) i5-1135G7 @ 2.40GHz. The RAM is 16GB. MHT proof proves that the value V of the i-th leaf node is in a MHT tree with the root R. In the verification, V and i are not disclosed, and only the generated proof and the root R are needed.  
   
1. Compile  
```shell
cd experiment
mkdir build; cd build; cmake ..; make
```
2. Setup  
```shell
cd merkle
./merkle setup
```
3. Prove  
// The depth of the MHT is set to 4, which can be modified in the main.cpp. We randomly generate the values of the leaf nodes for the tree. [index] refers to the index of the leaf node that needs to be proved. For example, [index] can be 3. Record the root value of the tree, which is used in the verification.   
```shell
./merkle prove [index]
``` 
4. Verify    
// The root value is needed.  
```shell
./merkle verify [root]
```


The simulation of the Register algorithm and the Trace algorithm can be found in the experiment/miracl directory.  Our environment is the Visual Studio 2012 in a laptop with Intel(R) Core(TM) i5-1135G7 @ 2.40GHz. The steps to run the code are as follows:  
1. Download the Miracl library from https://github.com/miracl/MIRACL. Unzip the MIRACL-master zip file.   
2.	In the Visual Studio, first create a new project: File->New->Project->Visual C++ project ->Win32 console Application->Fill the name of the project->application setting->Empty Project.  
3.	In the Solution Explorer of the project, right click Header Files->Add ->Existing Item-> Choose the big.h, ecn.h, ecn2.h, zzn.h, zzn12a.h, zzn2.h,zzn4.h in the unzipped MIRACL-master directory. Moreover, right click Source Files->Add ->Existing item->Choose the big.cpp, bn_pair.cpp, ecn.cpp, ecn2.cpp,zzn.cpp,zzn12a.cpp,zzn2.cpp,zzn4.cpp in the MIRACL-master directory and test.cpp in the miracl directory, which simulates our Register and Trace algorithms. Right Click Resource Files->Add-> Existing item->choose the miracl.lib in the miracl directory.      
4.	For the properties of the project, choose PROJECT at the menu bar->Properties->Configuration Properties->   
    - General->Use of MFC->choose Use MFC in a Static Library;   
    - C/C++->Additional Include Directories: the path of the include directory under the MIRACL-master directory. Make sure big.h, ecn.h, ecn2.h, zzn.h, zzn12a.h, zzn2.h,zzn4.h are in the include directory. If not, copy it to the include directory from the MIRACL-master directory;  
    - C/C++->Precompiled headers: Precompiled Header->Not using Precompiled headers;  
    - Linker->General->Additional Library Directories: the path of the miracle.lib under the miracl directory;   
    - Linker->Input->Ignore Specific Default Libraries: LIBC.lib.    
5.	For the test.cpp, choose BUILD at the menu bar->build solution. Then choose DEBUG at the menu bar->Start without debugging. After that, we can see the simulation result.


References  
1. https://github.com/christianlundkvist/libsnark-tutorial  
2. https://github.com/howardwu/libsnark-tutorial  
3. https://github.com/StarLI-Trapdoor/libsnark_sample  
4. https://github.com/sec-bit/libsnark_abc 

