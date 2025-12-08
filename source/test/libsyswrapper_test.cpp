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


TEST(SECURE_SYSTEM_CALL_VP, Positive_ExecSuccess)
{
    int ret = secure_system_call_vp(
        "ls",        // argv[0]
        "-l",        // argv[1]
        "/tmp",      // argv[2]
        NULL
    );

    EXPECT_EQ(0, ret);
}

TEST(SECURE_SYSTEM_CALL_VP, Negative_ExecFailure)
{
    int ret = secure_system_call_vp(
        "this_command_does_not_exist",
        NULL
    );

    EXPECT_NE(0, ret);
}


TEST(SECURE_SYSTEM, SYSTEM_NULL_CHECK)
{
   EXPECT_NE(0, v_secure_system(" "));
   char pathdir[20]="test_folder";
   EXPECT_NE(0,v_secure_system("ls -l /tmp/* \n; echo 1 > /tmp/%s/debuglog.txt;echo >;cd ~;ls {/etc,/var}", pathdir));
}

TEST(SECURE_POPEN, VCLOSE_ExecFailure)
{
    FILE *fp = v_secure_popen("r", "definitely_missing_binary");
    ASSERT_TRUE(fp);

    int ret = v_secure_pclose(fp);

    EXPECT_EQ(255, ret);
}

TEST(SECURE_POPEN, POPEN_NULL_CHECK)
{
   FILE *fp = NULL;
   fp = v_secure_popen("r"," ");
   EXPECT_TRUE(fp);
   EXPECT_NE(-1,v_secure_pclose(fp));
}
TEST(SECURE_POPEN, ApplyFdOps_PopenWrite)
{
    FILE *fp = v_secure_popen("w", "cat > /tmp/apply_fdops_popen.txt");
    ASSERT_TRUE(fp);

    fprintf(fp, "hello\n");

    int ret = v_secure_pclose(fp);
    EXPECT_NE(-1, ret);
}

TEST(SECURE_SYSTEM, ApplyFdOps_PureDup2)
{
    int ret = v_secure_system("ls /nonexistent 2>&1 > /tmp/dup_case.txt");
    EXPECT_NE(0, ret);
}

TEST(SECURE_SYSTEM, ApplyFdOps_CloseOnly)
{
    int ret = v_secure_system("echo hello 2>&-");
    EXPECT_NE(0, ret);
}

TEST(SECURE_POPEN, Internal_WriteMode_Simple)
{
    FILE *fp = v_secure_popen(
        "w",
        "cat > /tmp/popen_wr_test.txt"
    );

    ASSERT_TRUE(fp);

    fprintf(fp, "hello\n");
    fprintf(fp, "world\n");

    int ret = v_secure_pclose(fp);
    EXPECT_NE(-1, ret);
}


TEST(SECURE_POPEN, Internal_ExecuteTask_Failure)
{
    FILE *fp = v_secure_popen(
        "r",
        "ls /definitely_missing_file"
    );

    ASSERT_TRUE(fp);

    int ret = v_secure_pclose(fp);
    EXPECT_NE(-1, ret);
}

TEST(SECURE_POPEN, Internal_WriteMode)
{
    FILE *fp = v_secure_popen("w", "cat > /tmp/popen_wr_test.txt");
    ASSERT_TRUE(fp);

    fprintf(fp, "hello\n");
    int ret = v_secure_pclose(fp);
    EXPECT_NE(-1, ret);
}

TEST(SECURE_POPEN, PositiveCase1)
{
    FILE *fp= NULL;
    fp = v_secure_popen("r","ip -4 route show default | grep default | awk '{print $5}'");
    EXPECT_TRUE(fp);
    EXPECT_NE(-1, v_secure_pclose(fp));
}


TEST(SECURE_SYSTEM,PositiveCase1)
{
    EXPECT_EQ(0,v_secure_system("ls -l /tmp/;ps -ef | head -n 5;ls /nonexistent_path 2> /tmp/secure_err.txt | wc -l;curl https://reqbin.com/ > /tmp/file.txt;ls -l /tmp > " TMP_FILE));
    int ret = v_secure_system(
        "echo %s %d %s > /tmp/format_test.txt",
        "hello", 42, "world"
    );

    EXPECT_EQ(0, ret);
}

TEST(SECURE_POPEN, Negative_Combined)
{
    FILE *fp = NULL;

    fp = v_secure_popen(
            "r",
            "ls /tmp/* ; "
            "echo > ; "
            "cd ~ ; "
            "ls {/etc,/var}"
         );

    ASSERT_TRUE(fp);
    int ret = v_secure_pclose(fp);
    EXPECT_NE(-1, ret);
}

TEST(SECURE_SYSTEM, MixedFdDirections)
{
    int ret = v_secure_system(
        "cat /etc/hosts 2>&1 | wc -l >> /tmp/mixed.txt"
    );
    EXPECT_EQ(0, ret);
}


TEST(SECURE_CALL, Subshell) {
    EXPECT_EQ(0, v_secure_system("(echo abc) ; echo done"));
}

TEST(SECURE_CALL, NegativeCase3) {
    EXPECT_NE(0, v_secure_system("cd ~"));
}

TEST(SECURE_CALL, NegativeCase4) {
    EXPECT_NE(0, v_secure_system("cp /path/to/file.txt ~/file.txt"));
}

TEST(SECURE_CALL, NegativeCase5) {
    EXPECT_NE(0, v_secure_system("ls {/etc,/var,/usr}"));
}

TEST(SECURE_CALL, NegativeCase6) {
    EXPECT_NE(0, v_secure_system("mv {file1.txt,file2.txt} /tmp"));
}

TEST(Parser, BacktickEval) {
    EXPECT_EQ(0, v_secure_system("echo `echo hi`"));
}

TEST(Parser, BacktickEval1) {
    EXPECT_EQ(0, v_secure_system("echo `date`"));
}

TEST(Parser, BacktickEval2) {
    EXPECT_EQ(0, v_secure_system("echo Number of files: `ls | wc -l`"));
}

TEST(Parser, BacktickEval3) {
    EXPECT_EQ(0, v_secure_system("(ls | wc -l) & echo Counting files in background"));
}
TEST(Parser, BacktickEval4) {
    EXPECT_EQ(0, v_secure_system("sleep 1 &"));
}
