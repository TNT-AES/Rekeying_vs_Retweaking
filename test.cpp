/** @file test.cpp
  */
#include "test.h"

using namespace std;

#define MN 16
#define KN 16

void test()
{
	ofstream fout;
	fout.open("test.txt");
	
	ALIGNED_TYPE_(u8, 16) Seedkey[KN] ;
	ALIGNED_TYPE_(u8, 16) plain[MN];
	ALIGNED_TYPE_(u8, 16) cipher[MN];
	ALIGNED_TYPE_(u8, 16) tweak[MN];
	
	for (u64 i = 0; i < MN; i++)
	{
		Seedkey[i] = i;
		plain[i] = i;
		tweak[i] = i;
		cipher[i] = 0;
	}

	TNT_AES_Retweak_ENC(
		cipher,
		plain,
		Seedkey,
		tweak,
		MN
	);
	
	fout << hex;
	fout << setfill('0');
	fout << "Key:" << endl;
	for (u64 i = 0; i < KN; i++)
	{
		fout << setw(2) << tweak[i] + '\0';
	}
	fout << endl;
	fout << "Tweak:" << endl;
	for (u64 i = 0; i < MN; i++)
	{
		fout << setw(2) << tweak[i] + '\0';
	}
	fout << endl;
	fout << "Plain:" << endl;
	for (u64 i = 0; i < MN; i++)
	{
		fout << setw(2) << plain[i] + '\0';
	}
	fout << endl;

	fout << "Cipher:" << endl;
	for (u64 i = 0; i < MN; i++)
	{
		fout << setw(2) << cipher[i] + '\0';
	}
	fout << endl;
	fout.close();

}

