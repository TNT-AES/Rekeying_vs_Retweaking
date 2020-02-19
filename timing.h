/** @file timing.h
 */
#ifndef TIMING_H__
#define TIMING_H__
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include "TNT_AES.h"

#ifdef _MSC_VER
unsigned long CurrentProcessorNumber(void);
__inline unsigned long long read_tsc(void);
#endif

#ifdef __GNUC__
inline unsigned long long read_tsc(void);
#endif

void setCPUaffinity();

void block_rndfill(unsigned char *buf, const int len);

int time_base(
    double *av,
    double *sig);

int time_AES_Rekey_ENC_enc16(
    double *av,
    double *sig,
    unsigned long long dataLengthInBytes);

int time_TNT_AES_Retweak_ENC_enc16(
    double *av,
    double *sig,
    unsigned long long dataLengthInBytes);

void timing();

#endif  //TIMING_H__