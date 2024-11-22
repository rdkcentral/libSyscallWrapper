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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secure_wrapper.h"

int main(/* int argc, char **argv */) {

	v_secure_system("echo %s %s %s %s", "1", "2", "3", "4");
	v_secure_system("echo %d `echo %d` %d %d", 1, 2, 3, 4);

	v_secure_system("echo -n TEST01:; echo %s", "PASS");
	v_secure_system("echo -n TEST02:; true  && echo PASS");
	v_secure_system("echo -n TEST03:; false || echo PASS");
	v_secure_system("echo -n TEST04:; true  && echo PASS || echo FAIL");
	v_secure_system("echo -n TEST05:; echo PASS | grep PASS || echo FAIL");
	v_secure_system("echo -n TEST06:; false && echo FAIL1 | echo FAIL2 || echo PASS");
	v_secure_system("echo -n TEST07:; true  || echo FAIL1 | echo FAIL2 && echo PASS");
	v_secure_system("echo -n TEST08:; echo FAIL  >/dev/null | grep FAIL || echo PASS");
	v_secure_system("echo -n TEST09:; echo FAIL &>/dev/null | grep FAIL || echo PASS");
	v_secure_system("echo -n TEST10:; ./FAIL 2>/dev/null || echo PASS");
	v_secure_system("echo -n TEST11:; ./FAIL 2>&1 | grep FAIL >/dev/null && echo PASS");
	v_secure_system("echo    TEST12:PASS > ./testfile; cat testfile");
	v_secure_system("echo -n TEST13: > ./testfile; echo PASS >> testfile; cat < testfile");
	v_secure_system("echo    TEST14:`echo FAIL >/dev/null; echo PASS`");
	v_secure_system("echo -n TEST15:; echo %s`echo %s`%s | grep %s >/dev/null && echo PASS || echo FAIL", "1%s", "2%s", "3%s", "1%s2%s3%s");
	v_secure_system("echo    TEST16:`%s 2>/dev/null || echo PASS`;", "echo FAIL");

	// security checks
	//v_secure_system("echo -n TESTxx:; echo FAIL >%s || echo PASS", "/dev/null");

	FILE *fp = v_secure_popen("w", "cat");
	if (fp != NULL) { // CID 109143 : Dereference null return value (NULL_RETURNS)
        	fprintf(fp, "popen write success\n");
		v_secure_pclose(fp);
	}

	char buf[1024];
	memset(buf, 0, sizeof(buf));
	fp = v_secure_popen("r", "echo popen read success");
	if (fp == NULL) {
		printf("v_secure_popen failed\n");
	} else {
		if (fgets(buf, sizeof(buf), fp) == NULL) {
		    printf("v_secure_popen read error\n");
		} else {
		    printf("%s", buf);
		}
		v_secure_pclose(fp);
	}

	secure_system_call_vp("echo", "legacy", "api", "PASS", NULL);

	return 0;
}
