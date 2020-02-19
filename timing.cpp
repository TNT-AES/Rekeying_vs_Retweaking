/** @file timing.cpp
 */
#ifdef __GNUC__
#include <sched.h>
#include <unistd.h> 
#endif

#include "timing.h"

using namespace std;

#ifdef _MSC_VER
#define DUAL_CORE

#if defined( DUAL_CORE )
#  define WINDOWS_LEAN_AND_MEAN
#  include <windows.h>
#endif
#include <string.h>
#include <math.h>

#include <intrin.h>
#pragma intrinsic( __rdtsc )

__inline unsigned long long read_tsc(void)
{
	return __rdtsc();
}

#if defined( _M_IX86 )
#if _M_IX86 == 500
#define PROCESSOR   "Pentium"
#elif _M_IX86 == 600
#define PROCESSOR   "P2/P3/P4"
#else
#define PROCESSOR   ""
#endif
#elif defined( _M_X64 )
#define PROCESSOR   "AMD64/EMT64"
#else
#define PROCESSOR   ""
#endif

#if defined( _WIN64 )

#define CurrentProcessorNumber GetCurrentProcessorNumber

#else

unsigned long CurrentProcessorNumber(void)
{
    __asm
    {
        mov     eax,1
        cpuid
        shr     ebx,24
        mov     eax, ebx
    }
}

#endif

void setCPUaffinity()
{
#if defined( DUAL_CORE ) && defined( _WIN32 )
    HANDLE ph;
    DWORD_PTR afp;
    DWORD_PTR afs;
    ph = GetCurrentProcess();
    if(GetProcessAffinityMask(ph, &afp, &afs))
    {
        afp &= (1 << CurrentProcessorNumber());
        if(!SetProcessAffinityMask(ph, afp))
        {
            printf("Couldn't set Process Affinity Mask\n\n");
        }
    }
    else
    {
        printf("Couldn't get Process Affinity Mask\n\n");
    }
#endif
}

#else
#ifdef __GNUC__
#include <sys/resource.h>
#include <x86intrin.h>
inline unsigned long long read_tsc(void)
{
#if defined(__i386__)
	unsigned long long cycles;
	__asm__ volatile (".byte 0x0f, 0x31" : "=A"(cycles));
	return cycles;
#else
#if defined(__x86_64__)
	unsigned int hi, lo;
	__asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
	return (((unsigned long long)lo) | ((unsigned long long)(hi)<<32));
#else
#error "Unsupported architecture for counting cycles"
#endif
#endif
}

void setCPUaffinity()
{
	cpu_set_t cpu_mask;
	CPU_SET(0x1, &cpu_mask);
	if(sched_setaffinity(getpid(), sizeof(cpu_mask), &cpu_mask) == -1 )
	{
		printf("Impossible to set CPU affinity...\n");
	}
}
#endif
#endif

#define RAND(a,b) (((a = 36969 * (a & 65535) + (a >> 16)) << 16) + \
	(b = 18000 * (b & 65535) + (b >> 16))  )

void block_rndfill(unsigned char *buf, const int len)
{
	static unsigned long a[2], mt = 1, count = 4;
	static unsigned char r[4];
	int                  i;

	if(mt) { mt = 0; *(unsigned long long*)a = read_tsc(); }

	for(i = 0; i < len; ++i)
	{
		if(count == 4)
		{
			*(unsigned long*)r = RAND(a[0], a[1]);
			count = 0;
		}

		buf[i] = r[count++];
	}
}

#define MAX_MESSAGE_LENGTH (1UL << 13UL)
#define SAMPLE1  1000
#define SAMPLE2 10000

#define TRUE  1
#define FALSE 0

int timeBase(double *av, double *sig)
{
	volatile int                 i, tol, lcnt, sam_cnt;
	volatile double              cy, av1, sig1;

	tol = 10; lcnt = sam_cnt = 0;
	while(!sam_cnt)
	{
		av1 = sig1 = 0.0;

		for(i = 0; i < SAMPLE1; ++i)
		{
			cy = (volatile double)read_tsc();
			cy = (volatile double)read_tsc() - cy;

			av1 += cy;
			sig1 += cy * cy;
		}

		av1 /= SAMPLE1;
		sig1 = sqrt((sig1 - av1 * av1 * SAMPLE1) / SAMPLE1);
		sig1 = (sig1 < 0.05 * av1 ? 0.05 * av1 : sig1);

		*av = *sig = 0.0;
		for(i = 0; i < SAMPLE2; ++i)
		{
			cy = (volatile double)read_tsc();
			cy = (volatile double)read_tsc() - cy;

			if(cy > av1 - sig1 && cy < av1 + sig1)
			{
				*av += cy;
				*sig += cy * cy;
				sam_cnt++;
			}
		}

		if(10 * sam_cnt > 9 * SAMPLE2)
		{
			*av /= sam_cnt;
			*sig = sqrt((*sig - *av * *av * sam_cnt) / sam_cnt);

			if(*sig > (tol / 100.0) * *av)
				sam_cnt = 0;
		}
		else
		{
			if(lcnt++ == 10)
			{
				lcnt = 0; tol += 5;
				if(tol > 30)
					return FALSE;
			}
			sam_cnt = 0;
		}
	}
	return TRUE;
}

int time_AES_Rekey_ENC_enc16(double *av, double *sig, unsigned long long dataLengthInBytes)
{
	volatile int       i, tol, lcnt, sam_cnt;
	volatile double    cy, av1, sig1;
	unsigned char      pt[4][MAX_MESSAGE_LENGTH];
	unsigned char      key[4][MAX_MESSAGE_LENGTH];

	for (int i = 0; i < 4; i++)
	{
		block_rndfill(pt[i], dataLengthInBytes);
		block_rndfill(key[i], dataLengthInBytes);
	}

	tol = 10; lcnt = sam_cnt = 0;
	while(!sam_cnt)
	{
		av1 = sig1 = 0.0;

		for(i = 0; i < SAMPLE1; ++i)
		{
			cy = (double)read_tsc();
			AES_Rekey_ENC(pt[0], pt[0], key[0], dataLengthInBytes);
			AES_Rekey_ENC(pt[1], pt[1], key[1], dataLengthInBytes);
			AES_Rekey_ENC(pt[2], pt[2], key[2], dataLengthInBytes);
			AES_Rekey_ENC(pt[3], pt[3], key[3], dataLengthInBytes);
			AES_Rekey_ENC(pt[0], pt[0], key[0], dataLengthInBytes);
			AES_Rekey_ENC(pt[1], pt[1], key[1], dataLengthInBytes);
			AES_Rekey_ENC(pt[2], pt[2], key[2], dataLengthInBytes);
			AES_Rekey_ENC(pt[3], pt[3], key[3], dataLengthInBytes);
			AES_Rekey_ENC(pt[0], pt[0], key[0], dataLengthInBytes);
			AES_Rekey_ENC(pt[1], pt[1], key[1], dataLengthInBytes);
			AES_Rekey_ENC(pt[2], pt[2], key[2], dataLengthInBytes);
			AES_Rekey_ENC(pt[3], pt[3], key[3], dataLengthInBytes);
			AES_Rekey_ENC(pt[0], pt[0], key[0], dataLengthInBytes);
			AES_Rekey_ENC(pt[1], pt[1], key[1], dataLengthInBytes);
			AES_Rekey_ENC(pt[2], pt[2], key[2], dataLengthInBytes);
			AES_Rekey_ENC(pt[3], pt[3], key[3], dataLengthInBytes);
			cy = (double)read_tsc() - cy;

			av1 += cy;
			sig1 += cy * cy;
		}

		av1 /= SAMPLE1;
		sig1 = sqrt((sig1 - av1 * av1 * SAMPLE1) / SAMPLE1);
		sig1 = (sig1 < 0.05 * av1 ? 0.05 * av1 : sig1);

		*av = *sig = 0.0;
		for(i = 0; i < SAMPLE2; ++i)
		{
			cy = (double)read_tsc();
			AES_Rekey_ENC(pt[0], pt[0], key[0], dataLengthInBytes);
			AES_Rekey_ENC(pt[1], pt[1], key[1], dataLengthInBytes);
			AES_Rekey_ENC(pt[2], pt[2], key[2], dataLengthInBytes);
			AES_Rekey_ENC(pt[3], pt[3], key[3], dataLengthInBytes);
			AES_Rekey_ENC(pt[0], pt[0], key[0], dataLengthInBytes);
			AES_Rekey_ENC(pt[1], pt[1], key[1], dataLengthInBytes);
			AES_Rekey_ENC(pt[2], pt[2], key[2], dataLengthInBytes);
			AES_Rekey_ENC(pt[3], pt[3], key[3], dataLengthInBytes);
			AES_Rekey_ENC(pt[0], pt[0], key[0], dataLengthInBytes);
			AES_Rekey_ENC(pt[1], pt[1], key[1], dataLengthInBytes);
			AES_Rekey_ENC(pt[2], pt[2], key[2], dataLengthInBytes);
			AES_Rekey_ENC(pt[3], pt[3], key[3], dataLengthInBytes);
			AES_Rekey_ENC(pt[0], pt[0], key[0], dataLengthInBytes);
			AES_Rekey_ENC(pt[1], pt[1], key[1], dataLengthInBytes);
			AES_Rekey_ENC(pt[2], pt[2], key[2], dataLengthInBytes);
			AES_Rekey_ENC(pt[3], pt[3], key[3], dataLengthInBytes);
			cy = (double)read_tsc() - cy;

			if(cy > av1 - sig1 && cy < av1 + sig1)
			{
				*av += cy;
				*sig += cy * cy;
				sam_cnt++;
			}
		}

		if(10 * sam_cnt > 9 * SAMPLE2)
		{
			*av /= sam_cnt;
			*sig = sqrt((*sig - *av * *av * sam_cnt) / sam_cnt);
			if(*sig > (tol / 100.0) * *av)
				sam_cnt = 0;
		}
		else
		{
			if(lcnt++ == 10)
			{
				lcnt = 0; tol += 5;
				if(tol > 30)
				{
					return FALSE;
				}
			}
			sam_cnt = 0;
		}
	}
	return TRUE;
}

int time_TNT_AES_Retweak_ENC_enc16(double *av, double *sig, unsigned long long dataLengthInBytes)
{
	volatile int       i, tol, lcnt, sam_cnt;
	volatile double    cy, av1, sig1;
	unsigned char      key[16];
	unsigned char      pt[4][MAX_MESSAGE_LENGTH];
	unsigned char      tweak[4][MAX_MESSAGE_LENGTH];

	block_rndfill(key, 16);
	for (int i = 0; i < 4; i++)
	{
		block_rndfill(pt[i], dataLengthInBytes);
		block_rndfill(tweak[i], dataLengthInBytes);
	}

	tol = 10; lcnt = sam_cnt = 0;
	while(!sam_cnt)
	{
		av1 = sig1 = 0.0;

		for(i = 0; i < SAMPLE1; ++i)
		{
			cy = (double)read_tsc();
			TNT_AES_Retweak_ENC(pt[0], pt[0], key, tweak[0], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[1], pt[1], key, tweak[1], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[2], pt[2], key, tweak[2], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[3], pt[3], key, tweak[3], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[0], pt[0], key, tweak[0], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[1], pt[1], key, tweak[1], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[2], pt[2], key, tweak[2], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[3], pt[3], key, tweak[3], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[0], pt[0], key, tweak[0], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[1], pt[1], key, tweak[1], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[2], pt[2], key, tweak[2], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[3], pt[3], key, tweak[3], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[0], pt[0], key, tweak[0], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[1], pt[1], key, tweak[1], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[2], pt[2], key, tweak[2], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[3], pt[3], key, tweak[3], dataLengthInBytes);
			cy = (double)read_tsc() - cy;

			av1 += cy;
			sig1 += cy * cy;
		}

		av1 /= SAMPLE1;
		sig1 = sqrt((sig1 - av1 * av1 * SAMPLE1) / SAMPLE1);
		sig1 = (sig1 < 0.05 * av1 ? 0.05 * av1 : sig1);

		*av = *sig = 0.0;
		for(i = 0; i < SAMPLE2; ++i)
		{
			cy = (double)read_tsc();
			TNT_AES_Retweak_ENC(pt[0], pt[0], key, tweak[0], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[1], pt[1], key, tweak[1], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[2], pt[2], key, tweak[2], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[3], pt[3], key, tweak[3], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[0], pt[0], key, tweak[0], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[1], pt[1], key, tweak[1], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[2], pt[2], key, tweak[2], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[3], pt[3], key, tweak[3], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[0], pt[0], key, tweak[0], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[1], pt[1], key, tweak[1], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[2], pt[2], key, tweak[2], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[3], pt[3], key, tweak[3], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[0], pt[0], key, tweak[0], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[1], pt[1], key, tweak[1], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[2], pt[2], key, tweak[2], dataLengthInBytes);
			TNT_AES_Retweak_ENC(pt[3], pt[3], key, tweak[3], dataLengthInBytes);
			cy = (double)read_tsc() - cy;

			if(cy > av1 - sig1 && cy < av1 + sig1)
			{
				*av += cy;
				*sig += cy * cy;
				sam_cnt++;
			}
		}

		if(10 * sam_cnt > 9 * SAMPLE2)
		{
			*av /= sam_cnt;
			*sig = sqrt((*sig - *av * *av * sam_cnt) / sam_cnt);
			if(*sig > (tol / 100.0) * *av)
				sam_cnt = 0;
		}
		else
		{
			if(lcnt++ == 10)
			{
				lcnt = 0; tol += 5;
				if(tol > 30)
				{
					return FALSE;
				}
			}
			sam_cnt = 0;
		}
	}
	return TRUE;
}

static unsigned long kl[1] = { 128 };

static unsigned long ml[] = { 
	1UL << 7UL,
	1UL << 8UL,
	1UL << 9UL,
	1UL << 10UL,
	1UL << 11UL,
	1UL << 12UL,
	1UL << 13UL
	};
static unsigned long al[] = { 
	1UL << 7UL,
	1UL << 8UL,
	1UL << 9UL,
	1UL << 10UL,
	1UL << 11UL,
	1UL << 12UL,
	1UL << 13UL
	};


static double et, dt;

void timing()
{
	ofstream fout;
	string fn = "TNT_AES_ENC_Timing.csv";
	double   a0, av, sig;
	int i, w;
	unsigned long long di;

	setCPUaffinity();

	fout.open( fn.c_str(), ios::app);
	fout.setf(ios::fixed);

	fout << "Encryption Average Timing" << endl;
	fout << setw(30) << "P_len(bytes)" << setw(30) << "AES_REKEY(cycles/byte)"<< setw(30) << "TNT_RETWEAK(cycles/byte)" << endl;
	while (timeBase(&a0, &sig) != TRUE) {}
	fout.setf(ios::fixed); 
	for (di = 0; di < sizeof(ml)/sizeof(ml[0]); di++)
	{
		fout << setw(30) << ml[di];

		while (time_AES_Rekey_ENC_enc16(&av, &sig, ml[di]) != TRUE) {}
		sig *= 100.0 / av;
		av = (int)(10.0 * (av - a0) / (16.0 * (ml[di]))) / 10.0;
		sig = (int)(10 * sig) / 10.0;
		fout << setw(20) << setprecision(2) << av << " ("  <<setw(6) << sig << "%)";
    
		while (time_TNT_AES_Retweak_ENC_enc16(&av, &sig, ml[di]) != TRUE) {}
		sig *= 100.0 / av;
		av = (int)(10.0 * (av - a0) / (16.0 * (ml[di]))) / 10.0;
		sig = (int)(10 * sig) / 10.0;
		fout << setw(20) << setprecision(2) << av << " ("  <<setw(6) << sig << "%)";
		fout << endl;
	}
	fout.unsetf(ios::fixed);
	fout.close();
}

