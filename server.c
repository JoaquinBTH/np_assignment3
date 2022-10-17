#include <stdio.h>
#include <stdlib.h>
/* You will to add includes here */
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <regex.h>
#include <pthread.h>
#include <signal.h>

static int uid = 10;

void printIpAddr(struct sockaddr_in addr)
{
  printf("Client connected from %d.%d.%d.%d:%d\n",
         addr.sin_addr.s_addr & 0xff,
         (addr.sin_addr.s_addr & 0xff00) >> 8,
         (addr.sin_addr.s_addr & 0xff0000) >> 16,
         (addr.sin_addr.s_addr & 0xff000000) >> 24,
         addr.sin_port);
}

void printIp6Addr(struct addrinfo *addr, struct sockaddr_in6 port, char *host)
{
  char ipString[40];
  memset(ipString, 0, 40);
  inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr), ipString, addr->ai_addrlen);
  if(strlen(ipString) == 0)
  {
    printf("Client connected from [%s]:%d\n", host, port.sin6_port);
  }
  else
  {
    printf("Client connected from [%s]:%d\n", ipString, port.sin6_port);
  }
}

typedef struct
{
  int clientSock;
  int uid;
  char name[12];
  char message[255];
} clientDetails;

typedef struct
{
  clientDetails *array;
  size_t used;
  size_t size;
} Array;

Array clients;

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void initArray(Array *arr, size_t initialSize)
{
  arr->array = malloc(initialSize * sizeof(clientDetails));
  arr->used = 0;
  arr->size = initialSize;
}

void insertClient(Array *arr, clientDetails client)
{
  pthread_mutex_lock(&clients_mutex);
  if (arr->used == arr->size)
  {
    arr->size += 5;
    arr->array = realloc(arr->array, arr->size * sizeof(clientDetails));
  }
  arr->array[arr->used++] = client;

  pthread_mutex_unlock(&clients_mutex);
}

void removeClient(Array *arr, int uid)
{
  pthread_mutex_lock(&clients_mutex);

  printf("Removing client\n");
  for (int i = 0; i < arr->used; i++)
  {
    if (arr->array[i].uid == uid)
    {
      for (int j = i; j < (arr->used - 1); j++)
      {
        arr->array[j] = arr->array[j + 1];
      }
      arr->used--;
      break;
    }
  }

  pthread_mutex_unlock(&clients_mutex);
}

void freeArray(Array *arr)
{
  pthread_mutex_lock(&clients_mutex);
  free(arr->array);
  arr->array = NULL;
  arr->used = arr->size = 0;
  pthread_mutex_unlock(&clients_mutex);
}

void sendMessage(char *message, int uid)
{
  pthread_mutex_lock(&clients_mutex);

  int message_len = strlen(message);

  for (int i = 0; i < clients.used; i++)
  {
    if (clients.array[i].uid != uid)
    {
      if (send(clients.array[i].clientSock, message, (size_t)message_len, MSG_NOSIGNAL) == -1)
      {
        printf("Write failed! %s\n", strerror(errno));
        break;
      }
    }
  }

  pthread_mutex_unlock(&clients_mutex);

  sleep(1);
}

void *handle_client(void *arg)
{
  char protocol[20];
  char okOrError[20];
  memset(okOrError, 0, 20);
  memset(protocol, 0, 20);
  strcpy(protocol, "Hello 1\n");
  int leave_flag = 0;

  clientDetails *currentClient = (clientDetails *)arg;

  // Send Protocol
  printf("Server protocol: %s", protocol);
  if ((send(currentClient->clientSock, &protocol, strlen(protocol), 0)) == -1)
  {
    printf("Send failed!\n");
    leave_flag = 1;
  }

  char nickname[50];
  memset(nickname, 0, 50);
  // Recieve nickname and check if it's good or not
  if (recv(currentClient->clientSock, &nickname, sizeof(nickname), 0) == -1)
  {
    printf("Recieve failed nickname!\n");
    leave_flag = 1;
  }
  else
  {
    char testNick[12];
    memset(testNick, 0, 12);
    for (int i = 0; i < 5; i++)
    {
      testNick[i] = nickname[i];
    }
    if (strcmp(testNick, "NICK ") == 0)
    {
      memset(testNick, 0, 12);
      for (int i = 0; i < 12; i++)
      {
        if (nickname[i + 5] != ' ' && nickname[i + 5] != '\n')
        {
          testNick[i] = nickname[i + 5];
        }
        else
        {
          break;
        }
      }
    }
    else
    {
      leave_flag = 1;
    }
    memset(currentClient->name, 0, 12);
    strcpy(currentClient->name, testNick);
    /* This is to test nicknames */
    char *expression = "^[A-Za-z0-9/_]+$";
    regex_t regularexpression;
    int reti;

    reti = regcomp(&regularexpression, expression, REG_EXTENDED);
    if (reti)
    {
      fprintf(stderr, "Could not compile regex.\n");
      exit(1);
    }

    int matches = 0;
    regmatch_t items;

    for (int i = 0; i < clients.used; i++)
    {
      if (strcmp(clients.array[i].name, currentClient->name) == 0)
      {
        matches++;
      }
    }

    if (strlen(currentClient->name) < 12 && matches == 0)
    {
      reti = regexec(&regularexpression, currentClient->name, matches, &items, 0);
      if (!reti && leave_flag == 0)
      {
        printf("Name is allowed\n");
        insertClient(&clients, *currentClient);
        // Send ok to client
        memset(okOrError, 0, 20);
        strcpy(okOrError, "OK\n");
        if (send(currentClient->clientSock, okOrError, strlen(okOrError), 0) == -1)
        {
          printf("Sending OK failed!\n");
        }
      }
      else
      {
        printf("%s is not accepted.\n", currentClient->name);
        leave_flag = 1;
        // Send no to client
        memset(okOrError, 0, 20);
        strcpy(okOrError, "ERROR\n");
        if (send(currentClient->clientSock, okOrError, strlen(okOrError), 0) == -1)
        {
          printf("Sending ERROR failed!\n");
        }
      }
    }
    else
    {
      printf("Name %s too long or already exists.\n", currentClient->name);
      leave_flag = 1;
      // Send no to client
      memset(okOrError, 0, 20);
      strcpy(okOrError, "ERROR\n");
      if (send(currentClient->clientSock, okOrError, strlen(okOrError), 0) == -1)
      {
        printf("Sending ERROR failed!\n");
      }
    }
    regfree(&regularexpression);
  }

  while (1)
  {
    if (leave_flag)
    {
      break;
    }
    memset(currentClient->message, 0, 255);
    if (recv(currentClient->clientSock, &currentClient->message, sizeof(currentClient->message), 0) == -1)
    {
      printf("Recieve failed message: %s\n", currentClient->message);
      printf("Error message: %s\n", strerror(errno));
      break;
    }
    else
    {
      char MSG[5];
      memset(MSG, 0, 5);
      strncpy(MSG, currentClient->message, 3);

      if ((strcmp(currentClient->message, "exit\n") == 0))
      {
        leave_flag = 1;
      }
      else if (strcmp(MSG, "MSG") != 0)
      {
        leave_flag = 1;
        memset(okOrError, 0, 20);
        strcpy(okOrError, "ERROR\n");
        if (send(currentClient->clientSock, &okOrError, strlen(okOrError), 0) == -1)
        {
          printf("Send failed!\n");
        }
      }
      else
      {
        // Make two implementations to seee which one is the favorable when correcting the assignment
        // 1. Perfectly fine implementation for netcat and the clients where they can send messages back and forth.

        /*
        char temp[255];
        memset(temp, 0, 255);
        memcpy(temp, &currentClient->message[4], sizeof(currentClient->message));
        memset(currentClient->message, 0, 255);
        sprintf(currentClient->message, "MSG %s %s", currentClient->name, temp);
        sendMessage(currentClient->message, currentClient->uid);
        */

        // 2. If the message has more MSG inside of it, restructure the messages to be sent one after another and be accepted by the tests.

        int nrOfNewlines = 0;
        int posOfNewlines[3] = {0, 0, 0};
        for (int i = 0; i < sizeof(currentClient->message); i++)
        {
          if (currentClient->message[i] == '\n')
          {
            posOfNewlines[nrOfNewlines] = i;
            nrOfNewlines++;
          }
        }

        for (int i = 0; i < nrOfNewlines; i++)
        {
          if (nrOfNewlines == 1 || i == 0)
          {
            char temp[255];
            memset(temp, 0, 255);
            memcpy(temp, &currentClient->message[4], (size_t)(posOfNewlines[i] - 3));
            char msg[300];
            memset(msg, 0, 300);
            sprintf(msg, "MSG %s %s", currentClient->name, temp);
            sendMessage(msg, currentClient->uid);
          }
          else
          {
            char temp[255];
            memset(temp, 0, 255);
            memcpy(temp, &currentClient->message[posOfNewlines[i - 1] + 5], (size_t)(posOfNewlines[i] - posOfNewlines[i - 1] - 4));
            char msg[300];
            memset(msg, 0, 300);
            sprintf(msg, "MSG %s %s", currentClient->name, temp);
            sendMessage(msg, currentClient->uid);
          }
        }
        memset(currentClient->message, 0, 255);
      }
    }
  }
  if (strcmp(strerror(errno), "Success") != 0)
  {
    printf("%s UID: %d\n", strerror(errno), currentClient->uid);
  }
  removeClient(&clients, currentClient->uid);
  close(currentClient->clientSock);
  free(currentClient);
  pthread_detach(pthread_self());

  return NULL;
}

int main(int argc, char *argv[])
{

  /* Do more magic */
  if (argc != 2)
  {
    printf("Usage: %s <ip>:<port> \n", argv[0]);
    exit(1);
  }

  /*
    Read first input, assumes <ip>:<port> syntax, convert into one string (Desthost) and one integer (port).
  */
  char *Desthost;
  char *Destport;

  int IPv6 = 0;

  if (argv[1][0] == '[')
  {
    // IPv6
    IPv6 = 1;
    char delim[] = "]";
    char delim2[] = ":";
    Desthost = strtok(argv[1], delim);
    Destport = strtok(NULL, delim2);
    memmove(Desthost, Desthost + 1, strlen(Desthost));
  }
  else
  {
    // IPv4
    char delim[] = ":";
    Desthost = strtok(argv[1], delim);
    Destport = strtok(NULL, delim);

    // Parse if DNS to see if it's IPv4 or IPv6
    struct addrinfo hint, *test;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(Desthost, Destport, &hint, &test) == -1)
    {
      printf("Failed to get addr info\n");
    }

    switch (test->ai_family)
    {
    case AF_INET:
      IPv6 = 0;
      break;
    case AF_INET6:
      IPv6 = 1;
      break;
    }
  }

  if (Desthost == NULL || Destport == NULL)
  {
    printf("Usage: %s <ip>:<port> \n", argv[0]);
    exit(1);
  }
  // *Desthost now points to a sting holding whatever came before the delimiter, ':'.
  // *Dstport points to whatever string came after the delimiter.

  /* Do magic */
  int port = atoi(Destport);

  int backLogSize = 10;
  int yes = 1;

  struct addrinfo hint, *servinfo, *p;
  int rv;
  int serverSock;
  pthread_t tid;

  if (IPv6 == 1)
  {
    struct sockaddr_in6 ipv6Addr;
    memset(&ipv6Addr, 0, sizeof(ipv6Addr));
    ipv6Addr.sin6_family = AF_INET6;
    ipv6Addr.sin6_port = htons(port);
    ipv6Addr.sin6_addr = in6addr_any;

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET6;
    hint.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(Desthost, Destport, &hint, &servinfo)) != 0)
    {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
      return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next)
    {
      if ((serverSock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
      {
        printf("Socket creation failed.\n");
        continue;
      }

      if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
      {
        perror("setsockopt failed!\n");
        exit(1);
      }

      rv = bind(serverSock, (struct sockaddr *)&ipv6Addr, sizeof(ipv6Addr));
      if (rv == -1)
      {
        perror("Bind failed!\n");
        close(serverSock);
        continue;
      }
      break;
    }

    if (p == NULL)
    {
      fprintf(stderr, "Server failed to create an apporpriate socket.\n");
      exit(1);
    }

    printf("[x]Listening on %s:%d \n", Desthost, port);

    rv = listen(serverSock, backLogSize);
    if (rv == -1)
    {
      perror("Listen failed!\n");
      exit(1);
    }

    struct sockaddr_in6 client6Addr;
    socklen_t client_size = sizeof(client6Addr);

    initArray(&clients, 5);

    int clientSock = 0;

    signal(SIGPIPE, SIG_IGN);

    while (1)
    {
      clientSock = accept(serverSock, (struct sockaddr *)&client6Addr, &client_size);
      if (clientSock == -1)
      {
        perror("Accept failed!\n");
      }

      printIp6Addr(servinfo, client6Addr, Desthost);

      clientDetails *currentClient = (clientDetails *)malloc(sizeof(clientDetails));
      memset(currentClient, 0, sizeof(clientDetails));
      currentClient->clientSock = clientSock;
      currentClient->uid = uid++;

      pthread_create(&tid, NULL, &handle_client, (void *)currentClient);
    }
  }
  else
  {
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(Desthost, Destport, &hint, &servinfo)) != 0)
    {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
      return 1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
      if ((serverSock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
      {
        printf("Socket creation failed.\n");
        continue;
      }

      if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
      {
        perror("setsockopt failed!\n");
        exit(1);
      }

      rv = bind(serverSock, p->ai_addr, p->ai_addrlen);
      if (rv == -1)
      {
        perror("Bind failed!\n");
        close(serverSock);
        continue;
      }
      break;
    }

    if (p == NULL)
    {
      fprintf(stderr, "Server failed to create an apporpriate socket.\n");
      exit(1);
    }

    printf("[x]Listening on %s:%d \n", Desthost, port);

    rv = listen(serverSock, backLogSize);
    if (rv == -1)
    {
      perror("Listen failed!\n");
      exit(1);
    }

    struct sockaddr_in clientAddr;
    socklen_t client_size = sizeof(clientAddr);

    initArray(&clients, 5);

    int clientSock = 0;

    signal(SIGPIPE, SIG_IGN);

    while (1)
    {
      clientSock = accept(serverSock, (struct sockaddr *)&clientAddr, &client_size);
      if (clientSock == -1)
      {
        perror("Accept failed!\n");
      }

      printIpAddr(clientAddr);

      clientDetails *currentClient = (clientDetails *)malloc(sizeof(clientDetails));
      memset(currentClient, 0, sizeof(clientDetails));
      currentClient->clientSock = clientSock;
      currentClient->uid = uid++;

      pthread_create(&tid, NULL, &handle_client, (void *)currentClient);
    }
  }

  freeaddrinfo(servinfo);
  close(serverSock);
  freeArray(&clients);
  return 0;
}