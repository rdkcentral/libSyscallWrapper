/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "gtest/gtest.h"
#include "secure_wrapper.h"
#define TMP_FILE "/tmp/debuglogfile1.txt"
#define ARP_CACHE_FILE "/tmp/debuglogfile2.txt"

int add(int num1,int num2)
{
    return (num1+num2);
}

TEST(Add, AddCase)
{
    EXPECT_EQ(30,add(10,20));
    EXPECT_EQ(50,add(30,20));
}

TEST(SECURE_SYSTEM, SYSTEM_NULL_CHECK)
{
   EXPECT_NE(0, v_secure_system(" "));
}

TEST(SECURE_POPEN, POPEN_NULL_CHECK)
{
   FILE *fp = NULL;
   fp = v_secure_popen("r"," ");
   EXPECT_TRUE(fp);
   EXPECT_NE(-1,v_secure_pclose(fp));
}

TEST(SECURE_SYSTEM,PositiveCase1)
{
    EXPECT_EQ(0,v_secure_system("ls -l /tmp/"));
}

TEST(SECURE_SYSTEM,PositiveCase2)
{
    EXPECT_EQ(0,v_secure_system("ps -ef | head -n 5"));
}

TEST(SECURE_SYSTEM,PositiveCase3)
{
    EXPECT_EQ(0,v_secure_system("curl https://reqbin.com/ > /tmp/file.txt"));
}

TEST(SECURE_SYSTEM,PositiveCase4)
{
    //Able to pass macro directly
   EXPECT_EQ(0,v_secure_system("ls -l /tmp > " TMP_FILE));
}

TEST(SECURE_CALL,NegativeCase1)
{
    //v_secure_system call could not able to understand the special charecter "*"
    EXPECT_NE(0,v_secure_system("ls -l /tmp/* \n"));
}

TEST(SECURE_CALL,NegativeCase2)
{
    char pathdir[20]="test_folder";
    // should not pass string variable to redirection
    EXPECT_NE(0,v_secure_system("echo 1 > /tmp/%s/debuglog.txt",pathdir));
}

TEST(SECURE_POPEN, PositiveCase1)
{
    FILE *fp= NULL;
    fp = v_secure_popen("r","ip -4 route show default | grep default | awk '{print $5}'");
    EXPECT_TRUE(fp);
    EXPECT_NE(-1, v_secure_pclose(fp));
}

TEST(SECURE_POPEN, PositiveCase2)
{
    FILE *fp= NULL;
    fp = v_secure_popen("r","ifconfig | grep 127 | awk '/inet/{print $4}' | cut -d '/' -f1");
    EXPECT_TRUE(fp);
    EXPECT_NE(-1,v_secure_pclose(fp));
}

TEST(SECURE_POPEN, NegativeCase1)
{
    char filepath[30]="/tmp/dedugref.txt";
    FILE *fp=NULL;
    fp = v_secure_popen("r","route -en > %s",filepath);
    EXPECT_FALSE(fp);
}

