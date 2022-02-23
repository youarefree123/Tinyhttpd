/* 
    提供更详尽的注释，参考代码有无关功能的小幅改动并附带改动说明，
    整体缩进风格也有改变，原版代码请移步 https://github.com/cbsheng/tinyhttpd
*/

    // 运行后会部署到随机的端口号，linux下查看http的报文头部可以键入命令：
    //  wget --debug http://127.0.0.1:43051(改成自己的port)/index.html
    //  可以查看到http的报文头
    // ---request begin---
    // GET /index.html HTTP/1.1
    // User-Agent: Wget/1.20.3 (linux-gnu)
    // Accept: */*
    // Accept-Encoding: identity
    // Host: 127.0.0.1:43051
    // Connection: Keep-Alive

    // ---request end---
    // HTTP request sent, awaiting response... 
    // ---response begin---
    // HTTP/1.0 200 OK
    // Server: jdbhttpd/0.1.0
    // Content-Type: text/html

    // ---response end---
    // 200 OK
    // Registered socket 3 for persistent reuse.
    // Length: unspecified [text/html]
    // Saving to: ‘index.html’

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
//#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>

#define ISspace(x) isspace((int)(x))                // 判断字符是否是空白符,并没有搞懂为什么要强制类型转换

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"  // 服务器名字


/*接收请求*/
void accept_request(int);

/*返回错误请求信息*/
void bad_request(int);

/*读取服务器的文件到socket*/
void cat(int, FILE*);

/*主要处理发生在执行 cgi 程序时出现的错误*/
void cannot_execute(int);

/*将错误信息写到perror并退出*/
void error_die(const char*);

/*处理cgi程序*/
void execute_cgi(int, const char*, const char*, const char*);

/*读取套接字的一行，回车换行都算一行的结束*/
int get_line(int,char*,int);

/*http响应的头部写进socket*/
void headers(int,const char*);

/*处理未找到请求的文件时的处理*/
void not_found(int);

/*把服务器文件返回浏览器，调用cat*/
void serve_file(int,const char*);

/*初始化http服务：建立套接字，绑定端口，监听； u_short ：无符号短整型*/
int startup(u_short*);

/*客户端请求方法不被支持时返回给客户端信息*/
void unimplemented(int);


/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client 
 */
/**********************************************************************/

/*参数 client 表示已经与客户端连接上了的socket的文件描述符*/
void accept_request(int client) {
    char buf[1024];        // 文件传输的通道
    int numchars;          // 记录每次从get_line函数中读取到的字符数
    char method[255];      // http的方法
    char url[255];
    char path[512];        // 记录url的具体路径

    size_t i , j;          // size_t == long long unsigned int (64位) / long unsigned int (非64位) 
    
    struct stat st;        // 描述一个linux系统文件系统中的文件属性的结构
    int cgi = 0;           // 判断是否是一个cgi程序
    char* query_string = NULL; //

    //读取http请求的第一行数据(request line)，请求方法存入method中
    numchars = get_line(client,buf,sizeof(buf));

    i = 0 , j = 0;
    //个人见解，加上 (i < sizeof(method)-1) 是请求行传输的字符数异常的情况防止下栈溢出
    while( !ISspace(buf[j]) && (i < sizeof(method)-1) ) {
        method[i] = buf[j];    // 这两行也可以简写为method[i++] = buf[j++]; 
        ++i; ++j;              // 原来这里是i++; j++; 但是使用++i ; ++j; 更好 
    }
    method[i] = '\0';          // 常识吧，字符串后加 \0

    // tinyhttp 实现了GET 和 POST 方法，所以除了这两个以外其他都直接发送错误信息
    // 使用strcasecmp 而不是 strcmp 是因为strcasecmp无视大小写比较字符串,方法名大小写不敏感
    if( strcasecmp(method,"GET") && strcasecmp(method,"POST") ) {
        unimplemented(client);
        return ;
    }

    // 如果是 POST 方法，需要将cgi参数设置为1，
    // 因为 tinyhttpd 的POST请求的一个测试就是传入字符给服务器，然后通过cgi程序改变界面颜色
    if( strcasecmp(method,"POST") == 0 ) {
        cgi = 1;
    }

    // 跳过所有的空白字符，因为传入的http报文方法字段后面还有很多空格
    // (j < sizeof(buf)) 判断条件依旧是防止溢出
    while( ISspace(buf[j]) && (j < sizeof(buf)) ) 
        ++j;   //原来这里是j++,修改原因同上


    i = 0;  // 原本这句是放在上一句前面的，然而其实i是在下一句才开始使用，所以移到了这里

    // 方法字段后面接的就是 URL 了,读取URL并保存在url数组中； 后面加的两个判断条件理由同上，防溢出
    while( !ISspace(buf[j]) && (i < sizeof(url)) && (j < sizeof(buf)) ) {
        url[i] = buf[j];
        ++i; ++j;      // 理由同上，对原版做出了一丢丢小修改
    }
    url[i] = '\0';


    // 如果请求的是 GET 方法的话
    // 使用GET方法时，请求参数和对应的值附加在URL后面，利用一个问号（'?'）间隔，
    // 代表URL的结尾与请求参数的开始，更详细的解释请百度。。。
    if( strcasecmp(method,"GET") == 0 ) {
        query_string = url; //将一个指针指向url

        // 遍历这个url数组,跳过字符 '?' 前的所有字符（其实就是整个URL地址）拿到 '?' 后的参数
        while( (*query_string != '?') && (*query_string != '\0') ) 
            ++query_string;
        
        // 直到找到了 '?' 或者没有 ‘?’ 
        // 如果找到了 ? ,说明请求会调用cgi，cgi标志位改成1
        if( *query_string == '?' ) {
            cgi = 1;
            *query_string = '\0';   // 将 ‘?’ 改成‘\0’ , 原本的url数组分为了两段，一段纯URL地址，一段参数
            ++query_string;         // 指针再向前一位，便指向了第二段的开头，即参数项 
        }  
    }

    // 现在的url数组，要么本来就是没有问号的，要么就是已经去了问号的前面那段
    // 那么index.html的路径就是当前目录htdocs文件夹和URL的拼接,结果传入path
    sprintf( path,"htdocs%s",url ); 


    // 如果path路径最后一个字符是以 / 结尾, 就拼接一个 "index.html"
    // 我也不知道为啥要这样，上面不就已经完成这步了吗？暂且理解为防止某些常见意外
    if( path[strlen(path)-1] == '/' )
        strcat(path,"index.html");

    // 查询目标文件是否存在
    // 如果不存在，读取后续的head 和 body 内容（垃圾数据了属于），并忽略，执行 not_found
    // int stat(const char * file_name, struct stat *buf);
    // stat()用来将参数file_name 所指的文件状态, 复制到参数buf 所指的结构中
    if( stat(path,&st) == -1 ) {
        while( (numchars > 0) && strcmp("\n",buf) )
            numchars = get_line( client, buf, sizeof(buf) );
        // 执行not_found,向客户端说明文件未找到
        not_found( client );
    } 
        // 如果文件存在，那么就与常量 S_IFMT 相与，判断文件的类型。详细介绍请自行百度
    else {
        // 如果还是目录，就要拼接一个'index.html' , 大概还是为了健壮性才这么设计的吧。。 S_IFDIR 代表目录类型
        if( (st.st_mode & S_IFMT) == S_IFDIR )
            strcat( path, "/index.html" );
        
        // 如果该文件可执行（其实只设计了一个cgi文件的执行展示）,cgi 标志为1
        // S_IXUSR : 所有者拥有执行权限
        // S_IXGRP : 群组拥有执行权限
        // S_IXOTH : 其他用户拥有执行权限
        if( (st.st_mode & S_IXUSR) ||
            (st.st_mode & S_IXGRP) ||
            (st.st_mode & S_IXOTH) )
            cgi = 1;
        
        
        // 接下来如果有请求要用到cgi程序就调用，否则执行serve_file;
        if( !cgi ){
            serve_file( client, path );
            
        }
            
        else 
            execute_cgi( client, path, method, query_string );
 
    }

    close(client);
}


/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket 
 * 错误信息提示 */
/**********************************************************************/
void bad_request(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your browser sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat 
 */
/**********************************************************************/

// 读取文件到链接client的socket, FILE* resource ：指向文件的指针
void cat(int client, FILE* resource) {
    char buf[1024];
    fgets( buf, sizeof(buf), resource );
    while( !feof(resource) ) {
        //这里第三个参数是strlen(buf)是因为可能读不到1024个字节，比如读到文件尾或者一行没有1024那么长
        send(client, buf, strlen(buf), 0 );
        fgets(buf, sizeof(buf), resource ); // 重复直到读完
        
    }
}


/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
// 返回错误信息，没啥好说的
void cannot_execute(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}


/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
    //包含于<stdio.h>,基于当前的 errno 值，在标准错误上产生一条错误消息。参考《TLPI》P49
    perror(sc); 
    exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/

// 根据method执行对应操作，内容比较重要
void execute_cgi(int client, const char *path,const char *method, const char *query_string) {
    char buf[1024];
    int cgi_output[2];
    int cgi_input[2];
    pid_t pid;
    int status; 
    int i;
    char c;
    int numchars = 1;
    int content_length = -1;


    // 往 buf 中填东西以保证能进入下面的 while （buf里内容未初始化，所以为了保证第一次while循环自己填充点数据进去）
    buf[0] = 'A'; buf[1] = '\0';
    // 如果是 http 请求是 GET 方法的话读取并忽略请求剩下的内容 （POST方法才是申请执行cgi程序）
    if (strcasecmp(method, "GET") == 0)
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
    else {
        // POST
        numchars = get_line(client, buf, sizeof(buf));
        //这个循环的目的是读出指示 body 长度大小的参数，并记录 body 的长度大小。其余的 header 里面的参数一律忽略
        //注意这里只读完 header 的内容，body 的内容没有读
        while ( (numchars > 0) && strcmp("\n", buf) ) {
            buf[15] = '\0';
            if (strcasecmp(buf, "Content-Length:") == 0)
                content_length = atoi(&(buf[16])); //记录 body 的长度大小
            numchars = get_line(client, buf, sizeof(buf));
        }

        // 如果没有读出body大小，说明是错误报文，报错
        if( content_length == -1 ) {
            bad_request(client);
            return ;
        }
        }

        // 否则说明读取成功，发送OK
        sprintf(buf,"HTTP/1.0 200 OK\r\n");
        send( client, buf, strlen(buf), 0 );

        // 创建两个管道，用于进程间通信
        // int pipe(int filedes[2]);
        // 返回值：成功，返回0，否则返回-1。参数数组包含pipe使用的两个文件的描述符。fd[0]:读管道，fd[1]:写管道

        if( pipe(cgi_output) < 0) {
            cannot_execute( client );
            return;
        }
        if( pipe(cgi_input) < 0 ) {
            cannot_execute(client);
            return;
        }

        
        // 创建子进程来执行cgi脚本
        // fork调用的一个奇妙之处就是它仅仅被调用一次，却能够返回两次，它可能有三种不同的返回值：
        // 1）在父进程中，fork返回新创建子进程的进程ID；
        // 2）在子进程中，fork返回0；
        // 3）如果出现错误，fork返回一个负值；
        if( (pid = fork()) < 0 ) {
            cannot_execute(client);
            return;
        } 

        if( pid == 0 ) {
            // 子进程执行cgi 脚本,如果没兴趣可以不看，不是http内容
            char meth_env[255];
            char query_env[255];
            char length_env[255];

            //dup2()包含<unistd.h>中，参读《TLPI》P97
            //将子进程的输出由标准输出重定向到 cgi_ouput 的管道写端上
            dup2(cgi_output[1], 1);
            //将子进程的输出由标准输入重定向到 cgi_ouput 的管道读端上
            dup2(cgi_input[0], 0);
            //关闭 cgi_ouput 管道的读端与cgi_input 管道的写端
            close(cgi_output[0]);
            close(cgi_input[1]);
            
            //构造一个环境变量
            sprintf(meth_env, "REQUEST_METHOD=%s", method);
            //putenv()包含于<stdlib.h>中，参读《TLPI》P128
            //将这个环境变量加进子进程的运行环境中
            putenv(meth_env);
            
            //根据http 请求的不同方法，构造并存储不同的环境变量
            if (strcasecmp(method, "GET") == 0) {
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
            }
            else {   /* POST */
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
            }
            
            //execl()包含于<unistd.h>中，参读《TLPI》P567
            //最后将子进程替换成另一个进程并执行 cgi 脚本
            execl(path, path, NULL);
            exit(0);
        }
        else {
            // 父进程
            //父进程则关闭了 cgi_output管道的写端和 cgi_input 管道的读端
            close(cgi_output[1]);
            close(cgi_input[0]);
            
            //如果是 POST 方法的话就继续读 body 的内容，并写到 cgi_input 管道里让子进程去读
            if (strcasecmp(method, "POST") == 0)
            for (i = 0; i < content_length; i++) {
                recv(client, &c, 1, 0);     // 通过TCP 一个字符一个字符读
                write(cgi_input[1], &c, 1); // 然后写入管道
            }
            
            //然后从 cgi_output 管道中读子进程的输出，并发送到客户端去
            while (read(cgi_output[0], &c, 1) > 0)
            send(client, &c, 1, 0);

            //关闭管道
            close(cgi_output[0]);
            close(cgi_input[1]);
            //等待子进程的退出
            waitpid(pid, &status, 0);
        }

}


/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor    
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
// 从sock中读取一行，存入buf中，size是buf的最大长度 ,返回值是实际读取到的字符数
int get_line( int sock, char *buf, int size ) {
    int i = 0;
    char c = '\0';
    int n ;

    while( (i < size-1 ) && (c != '\n') ) {
        n = recv( sock, &c, 1, 0 );
        if( n > 0 ) {
            if( c == '\r' ) {
                // 通常flags设置为0，此时recv()函数读取tcp 缓冲区中的数据到buf中，并从tcp 缓冲区中移除已读取的数据。
                // 如果把flags设置为MSG_PEEK，仅仅是把tcp 缓冲区中的数据读取到buf中，
                // 没有把已读取的数据从tcp 缓冲区中移除，如果再次调用recv()函数仍然可以读到刚才读到的数据
                n = recv( sock, &c, 1, MSG_PEEK );
                // 报文中 \r 后 接 \n 如果没有要加上
                if( (n > 0) && (c == '\n') ) 
                    recv( sock, &c, 1, 0);
                else 
                    c = '\n';
            }
            buf[i] = c;  // 读取完毕
            ++i;
        }
        else 
            c = '\n'; // 否则没读到字符也说明读完了
    }

    buf[i] = '\0'; 
    return i;
}



/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/

// 把文件的基本信息封装成resopnse的头部 (实际上就做了一下强制类型转换？？不懂什么操作)
void headers(int client, const char *filename) {
    char buf[1024];
    
    // 是不是转成了这样子方便传输？
    (void)filename;  /* could use filename to determine file type */
    
    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);             // 自定义常量，在代码开头有解释
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}


/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/

void not_found(int client) {
    char buf[1024];

    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);            
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
// 发送文件给客户端
void serve_file(int client, const char *filename) {
    FILE* resource = NULL;
    int numchars = 1;
    char buf[1024];
     // 确保 buf 里面有东西，能进入下面的 while 循环
    buf[0] = 'A'; buf[1] = '\0';
     // 循环作用是读取并忽略掉这个 http 请求的头部
    while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
        numchars = get_line(client, buf, sizeof(buf));

    // 打开文件
    resource = fopen( filename, "r" );
    if( resource == NULL )
        not_found(client);
    else {
        // 打开文件成功，封装这个文件基本信息作为response的头部,传给client
        headers( client, filename );
        // 文件内容作为respone的body，传给client
        cat( client,resource );
    }
    fclose(resource);
}



/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/

//  通过port开始监听（listen）返回一个套接字
//  如果端口为 0，则动态分配,端口并修改原始端口变量以反映实际端口
//  标准的一套流程： 创建socket，配置socket信息，绑定  
int startup(u_short *port)
{
    int httpd = 0;  // http服务器的套接字
    //sockaddr_in 是 IPV4的套接字地址结构。定义在<netinet/in.h>,参读《TLPI》P1202
    struct sockaddr_in name;
    
    // socket()用于创建一个用于 socket 的描述符，函数包含于<sys/socket.h>。参读《TLPI》P1153
    // 这里的PF_INET其实是与 AF_INET同义，具体可以参读《TLPI》P946
    // int socket(int af, int type, int protocol);
    // af:地址族，这里PF_INET是ipv4 
    // type: 套接字类型（数据传输方式）SOCK_STREAM 流格式套接字/面向连接的套接字 （其实也就是指使用TCP协议）
    // protocol： 填 0 表示 系统会自动推演出应该使用什么协议（应该是根据第二个参数来推）
    httpd = socket(PF_INET, SOCK_STREAM, 0);
    if (httpd == -1)
        error_die("socket");
  
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    //htons()，ntohs() 和 htonl()包含于<arpa/inet.h>, 参读《TLPI》P1199
    //将*port 转换成以网络字节序表示的16位整数
    name.sin_port = htons(*port);
    //INADDR_ANY是一个 IPV4通配地址的常量，包含于<netinet/in.h>
    //大多实现都将其定义成了0.0.0.0 参读《TLPI》P1187
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    
    //bind()用于绑定地址与 socket。参读《TLPI》P1153
    //如果传进去的sockaddr结构中的 sin_port 指定为0，这时系统会选择一个临时的端口号
    if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
        error_die("bind");
    
    //如果调用 bind 后端口号仍然是0，则手动调用getsockname()获取端口号
    if (*port == 0)  /* if dynamically allocating a port */
    {
        int namelen = sizeof(name);
        //getsockname()包含于<sys/socker.h>中，参读《TLPI》P1263
        //调用getsockname()获取系统给 httpd 这个 socket 随机分配的端口号
        if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
        error_die("getsockname");
        *port = ntohs(name.sin_port);
    }
    
    //最初的 BSD socket 实现中，backlog 的上限是5.参读《TLPI》P1156
    // listen 若成功则为0，若出错则为-1
    if (listen(httpd, 5) < 0) 
        error_die("listen");
    return(httpd); 
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client)
{
 char buf[1024];

    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

int main(void)
{
    int server_sock = -1;
    u_short port = 0;
    int client_sock = -1;
    //sockaddr_in 是 IPV4的套接字地址结构。定义在<netinet/in.h>,参读《TLPI》P1202
    struct sockaddr_in client_name;
    int client_name_len = sizeof(client_name);
    //pthread_t newthread;

    server_sock = startup(&port);
    printf("httpd running on port %d\n", port);

    while (1)
    {
        //阻塞等待客户端的连接，参读《TLPI》P1157 
        client_sock = accept(server_sock,
                            (struct sockaddr *)&client_name,
                            &client_name_len);
        if (client_sock == -1)
            error_die("accept");
        accept_request(client_sock);
        /*if (pthread_create(&newthread , NULL, accept_request, client_sock) != 0)
        perror("pthread_create");*/
    }

    close(server_sock);

    return(0);
}


