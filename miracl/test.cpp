/*
   

   Compile with modules as specified in the selected header file

   For MR_PAIRING_CP curve
   cl /O2 /GX bls.cpp cp_pair.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
   (Note this really doesn't make much sense as the signature will not be "short")

   For MR_PAIRING_MNT curve
   cl /O2 /GX bls.cpp mnt_pair.cpp zzn6a.cpp ecn3.cpp zzn3.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
	
   For MR_PAIRING_BN curve
   cl /O2 /GX bls.cpp bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_KSS curve
   cl /O2 /GX bls.cpp kss_pair.cpp zzn18.cpp zzn6.cpp ecn3.cpp zzn3.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BLS curve
   cl /O2 /GX bls.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   Test program 
*/

#include <iostream>
#include <ctime>

//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security   
//#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256
//*********************************************

#include "pairing_3.h"

int main()
{   
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	miracl *mip=get_mip(); 
	Big r_p,sigma,ssk_R,a,c,z,V,p,RID,PIDm,PID_2;
	G1 g,g_1,g_2,g_3,g_4,g_5,g_bar,h,PID_1,R_p,P_pub,spk_R,T_1,T_2;

	clock_t start,finish,start1,finish1,start2,finish2;//define time variants
	double totaltime,totaltime1,totaltime2;

	time_t seed;

	time(&seed);
    irand((long)seed);
	//create constants in the scheme
	pfc.random(g);
	pfc.random(g_1);
	pfc.random(g_2);
	pfc.random(g_3);
	pfc.random(g_4);
	pfc.random(g_5);
	pfc.random(g_bar);
	pfc.random(h);
	pfc.precomp_for_mult(g);
	pfc.precomp_for_mult(g_1);  // g1 is fixed, so precompute on it
	pfc.precomp_for_mult(g_2);  
	pfc.precomp_for_mult(g_5);   
	pfc.precomp_for_mult(h); 
	p=pfc.order();

	start=clock();
	//Regulator generates P_pub,ssk_R,spk_R
	pfc.random(sigma);
	pfc.random(ssk_R);
	P_pub=pfc.mult(g,sigma);
	spk_R=pfc.mult(g,ssk_R);


	//user generates PID_1,R_p, and proof pi_r
	pfc.random(r_p); 
	PID_1=pfc.mult(g,r_p);
	R_p=pfc.mult(g_1,r_p);
    pfc.random(a);
	T_1=pfc.mult(g,a);
	T_2=pfc.mult(g_1,a);
	pfc.start_hash();
    pfc.add_to_hash(T_1);
    pfc.add_to_hash(T_2);
    c=pfc.finish_hash_to_group();
	z=(a+modmult(c,r_p,p))%p;
	

	//Regulator 
	   //verify pi_r
	if (pfc.mult(g,z)==T_1+pfc.mult(PID_1,c) && pfc.mult(g_1,z)==T_2+pfc.mult(R_p,c) )
	cout << "Proof pi_r verifies" << endl;
	else 
	cout << "Proof pi_r verification failed" << endl;
	pfc.random(V);
	  //generate PID_2
	mip->IOBASE=256;
	RID=(char *)"Alice12345678"; 
	cout << "RID is " << RID << endl;
	mip->IOBASE=16;
	pfc.start_hash();
    pfc.add_to_hash(pfc.mult(PID_1,sigma));
    pfc.add_to_hash(V);
    PIDm=pfc.finish_hash_to_group();
	PID_2=lxor(RID,PIDm);

	Big epsilon_0,phi_0;
	G1 cID_0;
	//generate cID
	pfc.random(epsilon_0);
	pfc.random(phi_0);
	cID_0=pfc.mult(g_1,r_p)+pfc.mult(g_2,V)+pfc.mult(g_5,epsilon_0)+pfc.mult(h,phi_0);
	//cout << "cID_0 is" << cID_0.g<< endl;

	//geenrate signature for PID and cID_0 with ssk_R,PID=(PID_1,PID_2)
	Big k_1,k_2,r1,r2,s1,s2,cIDx,s1_m,s2_m,HPID;
	G1 R_1,R_2;
	pfc.random(k_1);
	R_1=pfc.mult(g,k_1);
	R_1.g.get(r1);
	
	
	pfc.start_hash();
    pfc.add_to_hash(PID_1);
    pfc.add_to_hash(PID_2);
    HPID=pfc.finish_hash_to_group();
	s1_m=HPID+modmult(r1,ssk_R,p)%p;
	s1=modmult(inverse(k_1,p),s1_m,p); //(s1,r1) is the signature on PID


	pfc.random(k_2);
	R_2=pfc.mult(g,k_2);
    R_2.g.get(r2);
	cID_0.g.get(cIDx);
	s2_m=cIDx+modmult(r2,ssk_R,p)%p; 
	s2=modmult(inverse(k_2,p),s2_m,p); //(s2,r2) is the signature on cID_0

	//user verification
	  //verify (s1,r1),which is the signature on PID
	Big w,u_1,u_2,Rbarx;
	G1 Rbar;
	pfc.start_hash();
    pfc.add_to_hash(PID_1);
    pfc.add_to_hash(PID_2);
    HPID=pfc.finish_hash_to_group();
	w=inverse(s1,p);
	u_1=modmult(HPID,w,p);
	u_2=modmult(r1,w,p);
	Rbar=pfc.mult(g,u_1)+pfc.mult(spk_R,u_2);
	Rbar.g.get(Rbarx);
	
	if (Rbarx==r1 )
	cout << "signature on PID verifies" << endl;
	else 
	cout << "signature verification on PID  failed" << endl;

	//verify (s2,r2),which is the signature on cID_0
	Big W,U_1,U_2,Rhatx,RID1;
	G1 Rhat;
	cID_0.g.get(cIDx); //cIDx 
	W=inverse(s2,p);
	U_1=modmult(cIDx,W,p);
	U_2=modmult(r2,W,p);
	Rhat=pfc.mult(g,U_1)+pfc.mult(spk_R,U_2);
	Rhat.g.get(Rhatx);
	if (Rhatx==r2 )
	cout << "signature on cID_0 verifies" << endl;
    else 
    cout << "signature verification on cID_0  failed" << endl;
	finish=clock();
	totaltime=(double)((finish-start)); 
	 //cout<<"Total time for Register = "<<totaltime<<" ms"<<endl;

	//Trace
	  //verify PID_1=g^r_p
	start1=clock();
	if (pfc.mult(g,z)==T_1+pfc.mult(PID_1,c))
	cout << "Proof of r_p verifies" << endl;
	else 
	cout << "Proof of r_p failed" << endl;

	pfc.start_hash();
    pfc.add_to_hash(pfc.mult(PID_1,sigma));
    pfc.add_to_hash(V);
    PIDm=pfc.finish_hash_to_group();
	RID1=lxor(PID_2,PIDm);
	mip->IOBASE=256;
	cout << "Recovered RID is " << RID1 <<endl;
	finish1=clock();
	totaltime1=(double)((finish1-start1)); 
	// cout<<"Total time for Trace= "<<totaltime1<<" ms"<<endl;
	return 0;
}


	


