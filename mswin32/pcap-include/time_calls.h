/*
 * Copyright (c) 2001
 *	Politecnico di Torino.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the Politecnico
 * di Torino, and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef _time_calls
#define _time_calls

#ifdef WIN_NT_DRIVER

#include "debug.h"
#include "ndis.h"

#define	DEFAULT_TIMESTAMPMODE	0

#define TIMESTAMPMODE_SINGLE_SYNCHRONIZATION		0
#define TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP	1
#define TIMESTAMPMODE_QUERYSYSTEMTIME			2
#define TIMESTAMPMODE_RDTSC				3

#define TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_NO_FIXUP	99

#define TIMESTAMPMODE_REGKEY L"TimestampMode"

extern ULONG TimestampMode;

/*!
  \brief A microsecond precise timestamp.

  included in the sf_pkthdr or the bpf_hdr that NPF associates with every packet. 
*/

struct timeval {
        long    tv_sec;         ///< seconds
        long    tv_usec;        ///< microseconds
};

#endif /*WIN_NT_DRIVER*/

struct time_conv
{
	ULONGLONG reference;
	struct timeval start[32];
};

#ifdef WIN_NT_DRIVER

__inline void TIME_DESYNCHRONIZE(struct time_conv *data)
{
	data->reference = 0;
//	data->start.tv_sec = 0;
//	data->start.tv_usec = 0;
}


__inline void ReadTimeStampModeFromRegistry(PUNICODE_STRING RegistryPath)
{
	ULONG NewLength;
	PWSTR NullTerminatedString;
	RTL_QUERY_REGISTRY_TABLE Queries[2];
	ULONG DefaultTimestampMode = DEFAULT_TIMESTAMPMODE;

	NewLength = RegistryPath->Length/2;
	
	NullTerminatedString = ExAllocatePool(PagedPool, (NewLength+1) *sizeof(WCHAR));
	
	if (NullTerminatedString != NULL)
	{
		RtlCopyMemory(NullTerminatedString, RegistryPath->Buffer, RegistryPath->Length);
				
		NullTerminatedString[NewLength]=0;

		RtlZeroMemory(Queries, sizeof(Queries));
		
		Queries[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
		Queries[0].Name = TIMESTAMPMODE_REGKEY;
		Queries[0].EntryContext = &TimestampMode;
		Queries[0].DefaultType = REG_DWORD;
		Queries[0].DefaultData = &DefaultTimestampMode;
		Queries[0].DefaultLength = sizeof(ULONG);

		if (RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, NullTerminatedString, Queries, NULL, NULL) != STATUS_SUCCESS)
		{
			TimestampMode = DEFAULT_TIMESTAMPMODE;
		}

		RtlWriteRegistryValue(	RTL_REGISTRY_ABSOLUTE, NullTerminatedString, TIMESTAMPMODE_REGKEY,  REG_DWORD, &TimestampMode,sizeof(ULONG));	
		ExFreePool(NullTerminatedString);
	}	
	else
		TimestampMode = DEFAULT_TIMESTAMPMODE;
}

#pragma optimize ("g",off)  //Due to some weird behaviour of the optimizer of DDK build 2600 

/* KeQueryPerformanceCounter TimeStamps */
__inline void SynchronizeOnCpu(struct timeval *start)
{
//	struct timeval *start = (struct timeval*)Data;

	struct timeval tmp;
	LARGE_INTEGER SystemTime;
	LARGE_INTEGER i;
	ULONG tmp2;
	LARGE_INTEGER TimeFreq,PTime;

	// get the absolute value of the system boot time.   
	
	PTime = KeQueryPerformanceCounter(&TimeFreq);
	KeQuerySystemTime(&SystemTime);
	
	start->tv_sec = (LONG)(SystemTime.QuadPart/10000000-11644473600);

	start->tv_usec = (LONG)((SystemTime.QuadPart%10000000)/10);

	start->tv_sec -= (ULONG)(PTime.QuadPart/TimeFreq.QuadPart);

	start->tv_usec -= (LONG)((PTime.QuadPart%TimeFreq.QuadPart)*1000000/TimeFreq.QuadPart);

	if (start->tv_usec < 0)
	{
		start->tv_sec --;
		start->tv_usec += 1000000;
	}
}	

/*RDTSC timestamps			*/
/* callers must be at IRQL=PASSIVE_LEVEL*/
__inline VOID TimeSynchronizeRDTSC(struct time_conv *data)
{
	struct timeval tmp;
	LARGE_INTEGER system_time;
	ULONGLONG curr_ticks;
	KIRQL old;
	LARGE_INTEGER start_kqpc,stop_kqpc,start_freq,stop_freq;
	ULONGLONG start_ticks,stop_ticks;
	ULONGLONG delta,delta2;
	KEVENT event;
	LARGE_INTEGER i;
	ULONGLONG reference;

   	if (data->reference!=0)
		return;
	
	KeInitializeEvent(&event,NotificationEvent,FALSE);

	i.QuadPart=-3500000;

	KeRaiseIrql(HIGH_LEVEL,&old);
	start_kqpc=KeQueryPerformanceCounter(&start_freq);
	__asm
	{
		push eax
		push edx
		push ecx
		rdtsc
		lea ecx, start_ticks
		mov [ecx+4], edx
		mov [ecx], eax
		pop ecx
		pop edx
		pop eax
	}

	KeLowerIrql(old);
	
    	KeWaitForSingleObject(&event,UserRequest,KernelMode,TRUE ,&i);

	KeRaiseIrql(HIGH_LEVEL,&old);
	stop_kqpc=KeQueryPerformanceCounter(&stop_freq);
	__asm
	{
		push eax
		push edx
		push ecx
		rdtsc
		lea ecx, stop_ticks
		mov [ecx+4], edx
		mov [ecx], eax
		pop ecx
		pop edx
		pop eax
	}
	KeLowerIrql(old);

	delta=stop_ticks-start_ticks;
	delta2=stop_kqpc.QuadPart-start_kqpc.QuadPart;
	if (delta>10000000000)
	{
		delta/=16;
		delta2/=16;
	}

	reference=delta*(start_freq.QuadPart)/delta2;
	
	data->reference=reference/1000;

	if (reference%1000>500) 
		data->reference++;

	data->reference*=1000;

	reference=data->reference;
		
	KeQuerySystemTime(&system_time);

	__asm
	{
		push eax
		push edx
		push ecx
		rdtsc
		lea ecx, curr_ticks
		mov [ecx+4], edx
		mov [ecx], eax
		pop ecx
		pop edx
		pop eax
	}
	
	tmp.tv_sec=-(LONG)(curr_ticks/reference);

	tmp.tv_usec=-(LONG)((curr_ticks%reference)*1000000/reference);

	system_time.QuadPart-=116444736000000000;
	
	tmp.tv_sec+=(LONG)(system_time.QuadPart/10000000);
	tmp.tv_usec+=(LONG)((system_time.QuadPart%10000000)/10);
	
	if (tmp.tv_usec<0)
	{
		tmp.tv_sec--;
		tmp.tv_usec+=1000000;
	}

	data->start[0] = tmp;

	IF_LOUD(DbgPrint("Frequency %I64u MHz\n",data->reference);)
}

#pragma optimize ("g",on)  //Due to some weird behaviour of the optimizer of DDK build 2600 

__inline VOID TIME_SYNCHRONIZE(struct time_conv *data)
{
	ULONG NumberOfCpus, i;
	KAFFINITY AffinityMask;

	if (data->reference != 0)
		return;
		
	NumberOfCpus = NdisSystemProcessorCount();

	if ( TimestampMode ==  TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP || TimestampMode == TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_NO_FIXUP)
	{
		for (i = 0 ;  i < NumberOfCpus ; i++ )
		{
			AffinityMask = (1 << i);
			ZwSetInformationThread(NtCurrentThread(), ThreadAffinityMask, &AffinityMask, sizeof(KAFFINITY));
			SynchronizeOnCpu(&(data->start[i]));		
		}
		AffinityMask = 0xFFFFFFFF;
		ZwSetInformationThread(NtCurrentThread(), ThreadAffinityMask, &AffinityMask, sizeof(KAFFINITY));
		data->reference = 1;
 	}
	else
	if ( TimestampMode == TIMESTAMPMODE_QUERYSYSTEMTIME )
	{
		//do nothing
		data->reference = 1;
	}
	else
	if ( TimestampMode == TIMESTAMPMODE_RDTSC )
	{
		TimeSynchronizeRDTSC(data);
	}
	else
	{	//it should be only the normal case i.e. TIMESTAMPMODE_SINGLESYNCHRONIZATION
		SynchronizeOnCpu(data->start);
		data->reference = 1;
	}
	return;
}


#pragma optimize ("g",off)  //Due to some weird behaviour of the optimizer of DDK build 2600 

__inline void GetTimeKQPC(struct timeval *dst, struct time_conv *data)
{
	LARGE_INTEGER PTime, TimeFreq;
	LONG tmp;
	ULONG CurrentCpu;
	static struct timeval old_ts={0,0};


	PTime = KeQueryPerformanceCounter(&TimeFreq);
	tmp = (LONG)(PTime.QuadPart/TimeFreq.QuadPart);

	if (TimestampMode ==  TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP || TimestampMode == TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_NO_FIXUP)
	{
		//actually this code is ok only if we are guaranteed that no thread scheduling will take place. 
		CurrentCpu = KeGetCurrentProcessorNumber();	

		dst->tv_sec = data->start[CurrentCpu].tv_sec + tmp;
		dst->tv_usec = data->start[CurrentCpu].tv_usec + (LONG)((PTime.QuadPart%TimeFreq.QuadPart)*1000000/TimeFreq.QuadPart);
	
		if (dst->tv_usec >= 1000000)
		{
			dst->tv_sec ++;
			dst->tv_usec -= 1000000;
		}

		if (TimestampMode ==  TIMESTAMPMODE_SYNCHRONIZATION_ON_CPU_WITH_FIXUP)
		{
			if (old_ts.tv_sec > dst->tv_sec || (old_ts.tv_sec == dst->tv_sec &&  old_ts.tv_usec > dst->tv_usec) )
				*dst = old_ts;
	
			else
				old_ts = *dst;
		}
	}
	else
	{	//it should be only the normal case i.e. TIMESTAMPMODE_SINGLESYNCHRONIZATION
		dst->tv_sec = data->start[0].tv_sec + tmp;
		dst->tv_usec = data->start[0].tv_usec + (LONG)((PTime.QuadPart%TimeFreq.QuadPart)*1000000/TimeFreq.QuadPart);
	
		if (dst->tv_usec >= 1000000)
		{
			dst->tv_sec ++;
			dst->tv_usec -= 1000000;
		}
	}
}

__inline void GetTimeRDTSC(struct timeval *dst, struct time_conv *data)
{

	ULONGLONG tmp;
	__asm
	{
		push eax
		push edx
		push ecx
		rdtsc
		lea ecx, tmp
		mov [ecx+4], edx
		mov [ecx], eax
		pop ecx
		pop edx
		pop eax
	}

	if (data->reference==0)
	{
		return;
	}
	dst->tv_sec=(LONG)(tmp/data->reference);

	dst->tv_usec=(LONG)((tmp-dst->tv_sec*data->reference)*1000000/data->reference);
	
	dst->tv_sec+=data->start[0].tv_sec;

	dst->tv_usec+=data->start[0].tv_usec;

	if (dst->tv_usec>=1000000)
	{
		dst->tv_sec++;
		dst->tv_usec-=1000000;
	}


}

__inline void GetTimeQST(struct timeval *dst, struct time_conv *data)
{
	LARGE_INTEGER SystemTime;

	KeQuerySystemTime(&SystemTime);
	
	dst->tv_sec = (LONG)(SystemTime.QuadPart/10000000-11644473600);
	dst->tv_usec = (LONG)((SystemTime.QuadPart%10000000)/10);

}

#pragma optimize ("g",on)  //Due to some weird behaviour of the optimizer of DDK build 2600 


__inline void GET_TIME(struct timeval *dst, struct time_conv *data)
{

	if ( TimestampMode == TIMESTAMPMODE_RDTSC )
	{
		GetTimeRDTSC(dst,data);
	}
	else
	if ( TimestampMode == TIMESTAMPMODE_QUERYSYSTEMTIME )
	{
		GetTimeQST(dst,data);
	}
	else
	{
		GetTimeKQPC(dst,data);
	}
}


#else /*WIN_NT_DRIVER*/

__inline void FORCE_TIME(struct timeval *src, struct time_conv *dest)
{
	dest->start[0]=*src;
}

__inline void GET_TIME(struct timeval *dst, struct time_conv *data)
{
	*dst=data->start[0];
}

#endif /*WIN_NT_DRIVER*/


#endif /*_time_calls*/
