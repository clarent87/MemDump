#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <fcntl.h>

#define MAX_BUFF_LEN     1024
#define MAX_SEGMENT_SIZE 5120

typedef unsigned long ulong;

// 세그멘트 구조체. 이거 근데.. elf segment를 말하는거긴.. 하지.. 
typedef struct segment {
    ulong start;
    ulong end;
    char module_name[MAX_BUFF_LEN];
} segment;

// 문자열 소문자로 변환
void str_tolower(char *str)
{
    int i;
    for (i = 0; i < strlen(str); i++) {
        str[i] = (char) tolower(str[i]);
    }
}

// popen을 통한 shell commnad 실행... 
// shell commnad 결과에 feature와 같은 문자열이 있는지 확인하고 res에 저장한다. 
// ( 결과를 한줄씩 읽고 문자열 비교후 해당 줄을 저장.=> 하나라도 저장하면 바로 return..)
// popen의 전형적인 코드
// return은 성공여부 0이 return 되야 성공
int exec_command(const char* cmd, const char *feature, char *res)
{
    char buff[MAX_BUFF_LEN];
    FILE *fp = popen(cmd, "r");
    if (fp == NULL){
        printf("[*] Exec popen failed {%d, %s}\n", errno, strerror(errno));
        return -1;
    }
    while (fgets(buff, sizeof(buff), fp) != NULL){
        if (strstr(buff, feature) != NULL){
            strcpy(res, buff);
            return 0;
        }
    }
    fclose(fp); //이거 여기만 있는건 안될거 같은데.. 
    fp = NULL;
    return -2;
}

// 프로세스 이름으로 부터 pid 찾는 것일듯.. 
int get_process_pid(const char *process)
{
    char cmd[MAX_BUFF_LEN];
    char buff[MAX_BUFF_LEN];
    char running_process[MAX_BUFF_LEN];
    pid_t pid = 0;

    //search by ps commamd
    sprintf(cmd, "ps | grep %s", process);
    int res_code = exec_command(cmd, process, buff);
    if(res_code != 0){
        printf("[-] Exec command: %s failed\n", cmd);
    } else {
        pid_t running_pid;
        // sscanf에서 %*s처럼 *가 들어간 것은 생략한다는 것
        // 그리고 내 안드로이드는 ps가 아래 형식이 아닌데,, 잘 됬네.. ( 잘 동작했나??=> 한듯하네.. 희안하네.. ) => 안됬을듯.. 
        sscanf(buff, "%*s\t%d  %*d\t%*d %*d %*x %*x %*c %s", &running_pid, running_process);
        if (strcmp(running_process, process) == 0){
            pid = running_pid;
        }
    }

    //search by cmdline file ( PS 명령어로 해결 안됬을때 )
    if (pid > 0){
        return pid;
    }else{
        char file_name[MAX_BUFF_LEN];
        DIR *dir_proc;
        FILE *fp;
        if ((dir_proc = opendir("/proc")) == NULL){
            printf("[*] Exec opendir failed {%d, %s}\n", errno, strerror(errno));
            return 0;
        }
        struct dirent *dirent;
        while ((dirent = readdir(dir_proc)) != NULL){
            sprintf(file_name, "/proc/%s/cmdline", dirent->d_name);
            fp = fopen(file_name, "r");  // ex) /proc/1234/cmdline 파일을 연다.
            if (fp == NULL){
                continue;
            }
            fscanf(fp, "%s", running_process); // cmdline파일의 값 읽음..
            fclose(fp);
            fp = NULL;

            if (strcmp(running_process, process) == 0){ // 그리고 비교.. 근데 이때 파라메터가 전달되는 경우는 없어서 그냥 비교하나?
                pid = (uint32_t)atoi(dirent->d_name);
                break;
            }
        }
        closedir(dir_proc);
        return pid;
    }
}

// 이건 뭔지 모르겠네..
// 대충 마지막 thread의 이름을 반환하는데? ( id 값이 반환되는데.. 무슨 의미지?)
// task가 없는 경우는 process가 실행되지 않은거? 그런거 error 처리 하는건가..
int get_sub_pid(int pid) {
    char task_path[MAX_BUFF_LEN];
    sprintf(task_path, "/proc/%d/task/", pid); // 프로세스의 thread 정보 기록된곳.. ( 여기도 프로세스와 같이 maps도 있고 그럼.. )
    DIR *root_path = opendir(task_path);
    if (root_path == NULL) {
        printf("[-] Open dir %s failed {%d, %s}\n", task_path, errno, strerror(errno));
        return -1;
    }

    struct dirent *dirent = NULL;
    struct dirent *last_dirent = NULL;
    while ((dirent = readdir(root_path)) != NULL) {
        last_dirent = dirent; // 가장 마지막 거 찾네..
    }
    if (last_dirent == NULL) {
        printf("[-] Last dirent is null\n");
        return -1;
    }
    closedir(root_path);
    return atoi(last_dirent->d_name);
}

// 메모리 읽으려고 하는 부분 같다. 
// pid에 attach해서 mem 파일 handle 얻음 ( 아마 이렇게 해야 권한 문제가 없을듯..=> 즉 parent 가 되야.. => 그래야 자식 메모리 제어..   )
// handle == file discriptor
int attach_process(pid_t pid, int *handle) {
    char buff[MAX_BUFF_LEN];
    // https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
    sprintf(buff, "/proc/%d/mem", pid);
    long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (ret != 0) {
        printf("[-] Attach %d failed {%d, %s}\n", pid, errno, strerror(errno));
        return -1;
    } else {
        *handle = open(buff, O_RDONLY);
        if (handle == 0) {
            printf("[-] Open %s failed: %d, %s\n", buff, errno, strerror(errno));
            return -1;
        }
        return 0;
    }
}

// detach.
int detach_process(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
      perror(NULL);
      return -1;
    }
    return 0;
}

/*
목적 : maps 읽어서 내용 parsing 해서 segment array에 추가. 
pid는 pid
segments는 segment array
segment_size 는 어레이 받았으니까, size 도 받음. 

TODO : 연속되지 않을 수도 있으니 수정 ? 짜피 offset으로 작업하는게 좋을듯
*/
int read_maps(pid_t pid, segment *segments, int *segment_size)
{
    // maps 파일 열기
    char maps_path[MAX_BUFF_LEN];
    sprintf(maps_path, "/proc/%d/maps", pid);
    FILE *maps_handle = fopen(maps_path, "r");
    if (maps_handle == NULL) {
        printf("[-] Open %s failed: %d, %s\n", maps_path, errno, strerror(errno));
        return -1;
    }

    int index = 0;
    ulong start, end; // maps의 보면 start end address 같음. 
    char line[MAX_BUFF_LEN];
    char module_name[MAX_BUFF_LEN]; // maps의 so 이름. 
    char pre_module_name[MAX_BUFF_LEN]; // 아.. 이를테면 libnative.so는 load가 연속해서 3군데 되니까.  end 조정해주기 위함. 
    while (fgets(line, MAX_BUFF_LEN, maps_handle) != NULL) { // new line까지 한줄 읽는거 . 
        memset(module_name, 0, MAX_BUFF_LEN);
        //printf("[*] Content: %s", line);
        int rv = sscanf(line, "%lx-%lx %*s %*s %*s %*s %s", &start, &end, module_name);
        //printf("[*] Segment information:{start:0x%lx, end:0x%lx, name:%s}\n", start, end, module_name);
        if (rv != 3) {
            //printf("[-] Scanf failed: %d, %s\n", errno, strerror(errno));
            continue;
        } else { // 제대로 읽었을 경우.. => 세그멘트 구조체 세팅.. 
            str_tolower(module_name); // 모듈이름은 그냥 소문자로.. 
            if (strcmp(pre_module_name, module_name) == 0) {
                if (segments[index - 1].end < end) {
                    segments[index - 1].end = end;
                }
            } else {
                strcpy(pre_module_name, module_name);
                strcpy(segments[index].module_name, module_name);
                segments[index].start = start;
                segments[index].end = end;
                index++;
            }
        }
    }
    *segment_size = index;
    fclose(maps_handle);
    maps_handle = NULL;
    return 0;
}

// 근데 위에 꺼에서 같은 이름의 so가 있으면.. 문제 되는건 아닌가?( segments에 저장은 되겠지만.. 나중에 선택 할떄..)


/*
이게 실질적으로 dump 뜨는거 같음..
mem_handle 
start
end
output : 덤프 저장할 파일.
*/
int dump_module(int mem_handle, ulong start, ulong end, const char* output)
{
    ulong size = end - start;  // 읽을 size 계산.
    int res_code = 0;
    if (lseek(mem_handle, start, SEEK_SET) != -1) { // 역시 start위치로 file pointer이동.
        char *content = (char *) malloc(size * sizeof(char));
        ssize_t dump_size = read(mem_handle, content, size);  // 역시 content에 size많큼 읽는다. dump_size는 읽은 size만큼 나오는게 정상

        FILE *output_handle = fopen(output, "wb");
        if (fwrite(content, sizeof(char), dump_size, output_handle) == dump_size) {
            res_code = 0;
        } else {
            printf("[-] Write %s failed: %d, %s\n", output, errno, strerror(errno));
            res_code = -1;
        }
        fclose(output_handle);
        free(content);
        content = NULL;
        return res_code;
    } else {
        printf("[-] Lseek %d failed: %d, %s\n", mem_handle, errno, strerror(errno));
        return -1;
    }
}

int main(int argc, char const *argv[])
{
    char process[MAX_BUFF_LEN] = ""; // 프로세스 이름 주던지 아니면 pid 주던지.
    pid_t pid;
    ulong start;
    ulong end;
    char module[MAX_BUFF_LEN] = "";  // 원하는 so 이름 주던지.. 아니면 start-end 주던지.
    char output[MAX_BUFF_LEN] = "";

    strncpy(process, argv[1], strlen(argv[1]));
    pid = atoi(argv[2]);
    start = atoll(argv[3]);
    end = atoll(argv[4]);
    strncpy(module, argv[5], strlen(argv[5]));
    strncpy(output, argv[6], strlen(argv[6]));

    printf("[+] Input args: {process:%s, pid:%d, start:0x%lx, end:0x%lx, module:%s, output:%s}\n",
           process, pid, start, end, module, output);

    //check process or pid
    if (pid == 0){
        if (strncmp(process, "-", 1) == 0){
            printf("[-] Must input process or pid\n");
            return -1;
        }
        pid = get_process_pid(process);
        if(pid == 0 ){
            printf("[-] Can't find pid by process name\n");
            return -1;
        } else{
            printf("[+] Get %s pid: %d\n", process, pid);
        }
    }else{
         // pid 주어졌을 경우는 ps에 떠있는지 check를 해준다. 
        char cmd[MAX_BUFF_LEN];
        char buff[MAX_BUFF_LEN];
        char pid_str[MAX_BUFF_LEN];
        sprintf(pid_str, "%d", pid);
        sprintf(cmd, "ps | grep %d", pid);
        int res_code = exec_command(cmd, pid_str, buff);
        if(res_code != 0){
            printf("[-] Can't find process by pid: %d\n", pid);
            return -1; 
        }
        printf("[+] Find process by pid: %d\n", pid);
    }

    //get sub_pid
    //이거 왜이렇게 하는지 모르겠음.. 
    int sub_pid = get_sub_pid(pid);
    if(sub_pid != 0){
        printf("[+] Get sub pid:%d success\n", sub_pid);
        pid = sub_pid; // 서브 pid가 있으면 서브 pid로 바꾸네.. 
    }

    int mem_handle = 0;
    int res_code = attach_process(pid, &mem_handle); //  기본적으로 ptrace는 thread단위 적용가능
    if(res_code != 0){
        printf("[-] Attach pid:%d failed", pid);
        return -1;
    }
    printf("[+] Attach pid:%d success, handle: %d\n", pid, mem_handle);

    segment *segments = malloc(sizeof(segment) * MAX_SEGMENT_SIZE);
    int segment_size = 0;
    res_code = read_maps(pid, segments, &segment_size);
    if(res_code != 0){
        printf("[-] Read segment information failed\n");
    }
    printf("[+] Read segment information success, size: %d\n", segment_size);

    //check module name or scope address
    // 스코프가 주어진 경우
    if(start == 0 || end == 0){
        if(strncmp(module, "-", 1) == 0){
            printf("[-] Must input available module name or scope address\n");
            return -1;
        }
        int i = 0;
        int has_module = 0;
        for(i=0; i<segment_size; i++){ // while 돌면서 찾긴하네.. 근데 예상대로 이름으로는 가장 처음 만난것을 선택함.. 
            if(strstr(segments[i].module_name, module) != NULL){
                start = segments[i].start;
                end = segments[i].end;
                has_module = 1;
                printf("[+] Target segment information: {start:0x%lx, end:0x%lx, name:%s}\n", start, end, module);
                break;
            }
        }
        if(has_module == 0){
            printf("[-] Check input module name: %s\n", module);
            return -1;
        }
    }

    res_code = dump_module(mem_handle, start, end, output);
    if (res_code == 0){
        printf("[+] Dump %s success", output);
    }

    detach_process(pid);
    close(mem_handle);
    free(segments);
    return 0;
}
