/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>

#include "alog.h"

#define AT_SUCCESS                         0
#define AT_FAIL                           -1
#define AT_ASSERT_PASS                     0
#define AT_ASSERT_FAIL                    -1
#define AT_DATE_STRING_LENGTH             12
#define AT_TIME_STRING_LENGTH             10

#define LOGLIB_INDICATOR          "[LOGLIB]"
#define SPLIT_LINE  "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"

static char gCategory[AT_CATEGORY_MAX_LEN] = {0};
static char gCaseID[AT_CASEID_MAX_LEN] = {0};
static FILE* gFile = NULL;
static ALLOGFORMAT gType;
static ALLOGMEDIA gMedia;
static int gInitialized = 0;   /* 0: not yet, 1: initialized */
static char* strAErrorLevel[] = {"PASS", "FAIL", "INFO", "START", "END"};

static void alogGetTimeString(char* dateDest, char* timeDest);
static void alogPrintMessage(AErrorLevel el, char* buffer);
static void alogPrintCommon(AErrorLevel el, char* buffer);
static void alogProcessMessage(const char* source, char* dest);
static int alogInitChk();

int gNoLog = 0;

int ALogInit (const char* pszFileName, ALLOGFORMAT type, ALLOGMEDIA media)
{
	if(gNoLog == 1)
		return AT_SUCCESS;
	if(media & ALFILE)
	{
		if(pszFileName == NULL || strlen(pszFileName) < 1) goto FILEEX;

		if((gFile = fopen(pszFileName, AT_FILE_OPEN_MODE)) == NULL) goto FILEEX;

	}

	gType = type;
	gMedia = media;
	
    alogPrintMessage(START, SPLIT_LINE);
	return AT_SUCCESS;
FILEEX:
	printf("%s: Can't open the specified file!\n", LOGLIB_INDICATOR);
	return AT_FAIL;
}

void ALogClose()
{
	if(gNoLog == 1)
		return;
    strcpy(gCategory, "");
    strcpy(gCaseID, "");
    alogPrintMessage(END, SPLIT_LINE);

	if(gFile != NULL)
	{
		fclose(gFile);
	}
	gFile = NULL;
	gInitialized = 0;
}

void ALogPrint(const char* format, ...)
{
	char buffer[AT_MESSAGE_MAX_LEN * 2] = {0};
	va_list args;

	if(gNoLog == 1)
		return;
	if(strlen(format) >= AT_MESSAGE_MAX_LEN / 2)
	{
		printf("%s: Message is too long!\n", LOGLIB_INDICATOR);
		return;
	}
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

	alogPrintCommon(INFO, buffer);
}

void ALogPrintEx(AErrorLevel el, const char* format, ...)
{
	char buffer[AT_MESSAGE_MAX_LEN * 2] = {0};
	va_list args;

	if(gNoLog == 1)
		return;

	if(strlen(format) >= AT_MESSAGE_MAX_LEN)
	{
		printf("%s: Message is too long!\n", LOGLIB_INDICATOR);
		return;
	}
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

	alogPrintCommon(el, buffer);
}

int ALogSetCategory(const char* category)
{
	if(category == NULL || strlen(category) >= AT_CATEGORY_MAX_LEN || strlen(category) < 1)
	{
		printf("%s: Invalid case category!\n", LOGLIB_INDICATOR);
		gInitialized = 0;
		return AT_FAIL;
	}
	strcpy(gCategory, category);
	return AT_SUCCESS;
}

int ALogSetCaseID(const char* id)
{
	if(id == NULL || strlen(id) >= AT_CASEID_MAX_LEN || strlen(id) < 1)
	{
		printf("%s: Invalid case ID!\n", LOGLIB_INDICATOR);
		gInitialized = 0;
		return AT_FAIL;
	}
	strcpy(gCaseID, id);
	return AT_SUCCESS;
}


int ALogAssertTrue(int value)
{	
	if(value)
	{
		ALogPrintEx(PASS, "ASSERT passed!");
		return AT_ASSERT_PASS;
	}
	else
	{
		ALogPrintEx(FAIL, "ASSERT failed!");
		return AT_ASSERT_FAIL;
	}
}

int ALogAssertFalse(int value)
{
	return ALogAssertTrue(!value);
}


static void alogGetTimeString(char* dateDest, char* timeDest)
{
	time_t currentTime;

	time(&currentTime);               
	strftime(dateDest, AT_DATE_STRING_LENGTH, "%Y-%m-%d", localtime(&currentTime));
	strftime(timeDest, AT_TIME_STRING_LENGTH, "%H:%M:%S", localtime(&currentTime));
}

static int alogInitChk()
{
	if(gNoLog == 1)
		return 1;
	gInitialized = 1;

	if(strlen(gCategory) == 0 || strlen(gCaseID) ==0)
	{
		printf("%s: Please set category or case ID!\n", LOGLIB_INDICATOR);
		gInitialized = 0;
	}
	if((gMedia & ALFILE) && (gFile == NULL)) 
	{
		printf("%s: Probably, no file name is specified!\n", LOGLIB_INDICATOR);
		gInitialized = 0;
	}
	if(gType != ALCSV) 
	{
		printf("%s: Output format can only be CSV!\n", LOGLIB_INDICATOR);
		gInitialized = 0;
	}
	if(!(gMedia & ALFILE) && !(gMedia & ALCONSOLE))
	{
		printf("%s: Invalid output media!\n", LOGLIB_INDICATOR);
		gInitialized = 0;
	}

	return gInitialized;
}

static void alogProcessMessage(const char* source, char* dest)
{
	int pos = 0, i = 0;

	if(strchr(source, ',') != NULL || strchr(source, '\"') != NULL || strchr(source, '\n') != NULL)
	{
		dest[pos++] = '\"';
		while(source[i] != '\0')
		{
			dest[pos++] = source[i];
			if(source[i] == '\"')
			{
				dest[pos++] = '\"';
			}
			i++;
		}
		dest[pos++] = '\"';
		dest[pos] = '\0';
	}
	else
	{
		strcpy(dest, source);
	}
}


static void alogPrintMessage(AErrorLevel el, char* buffer)
{
	//size_t strLen = 0;
	int i;
	char date[AT_DATE_STRING_LENGTH] = {0};
	char time[AT_TIME_STRING_LENGTH] = {0};
	char message[AT_MESSAGE_MAX_LEN * 2];

	//printf("%d \n",buffer);
	//printf("%c \n",buffer[1]);
	//strLen = strlen(buffer);
	if(gNoLog == 1)
		return;
	for(i = 0; buffer[i] != 0; i++) {
		if(buffer[i] == '\n' || buffer[i] == '\r') {
			buffer[i] = ' ';
		}
	}
	//if(buffer[strLen - 1] == '\n')
	//{
	//	buffer[strLen - 1] = '\0';
	//}

	//printf("before alogGetTimeString\n");
	alogGetTimeString(date, time);
	//printf("before alogProcessMessage\n");
	alogProcessMessage(buffer, message);
	//printf("after alogProcessMessage\n");

	if(gMedia & ALFILE)
	{
		//printf("before fprint %d\n", gCategory[0]);
		fprintf(gFile, "%s,%s,%s,%s,%s,%s\n", gCategory, gCaseID, strAErrorLevel[el], date, time, message);  
		//printf("before fprint\n");
	}
#ifdef AT_FLUSH_AFTER_FPRINTF
	fflush(gFile);
#endif

	if(gMedia & ALCONSOLE)
	{
		printf("%s,%s,%s,%s,%s,%s\n", gCategory, gCaseID, strAErrorLevel[el], date, time, message);  
	}
}

static void alogPrintCommon(AErrorLevel el, char* buffer)
{
	if(gNoLog == 1)
		return;
	if(gInitialized != 1)
	{
		if(alogInitChk() != 1)
		{
			return;
		}
	}
    
    alogPrintMessage(el, buffer);
}
