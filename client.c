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
#include <curses.h>

#define DEBUG

char name[12];
char NICKname[17];
char messageName[17];

volatile sig_atomic_t flag = 0;

void catch_ctrl_c()
{
  flag = 1;
}

void str_overwrite_stdout()
{
  printf("\r");
  fflush(stdout);
}

void recv_msg_handler(void *arg)
{
  char message[255];

  int *socket = (int *)arg;

  while (1)
  {
    memset(message, 0, 255);
    int recieve = recv(*socket, message, sizeof(message), 0);
    if (recieve == -1)
    {
      printf("Recieve failed!\n");
      break;
    }
    else
    {
      bool same = true;
      for (int i = 0; i < strlen(messageName); i++)
      {
        if (messageName[i] != message[i])
        {
          same = false;
        }
      }
      if (same == false)
      {
        //Implementation for allowing the specific type of messages from the perl tests as well as any netcat or similar client messages to function properly!
        int nrOfNewlines = 0;
        int posOfNewlines[3] = {0, 0, 0};
        for(int i = 0; i < sizeof(message); i++)
        {
          if(message[i] == '\n')
          {
            posOfNewlines[nrOfNewlines] = i;
            nrOfNewlines++;
          }
        }

        for(int i = 0; i < nrOfNewlines; i++)
        {
          if(nrOfNewlines == 1 || i == 0)
          {
            char messageWithoutMSG[255];
            memset(messageWithoutMSG, 0, 255);
            int spacesFound = 0;
            for(int i = 0; i < ((int)strlen(message)); i++)
            {
              if(message[i] == ' ')
              {
                spacesFound++;
                if(spacesFound == 2)
                {
                  messageWithoutMSG[(int)strlen(messageWithoutMSG)] = ':';
                }
              }

              if(spacesFound > 0)
              {
                messageWithoutMSG[(int)strlen(messageWithoutMSG)] = message[i];
              }
            }
            char temp[255];
            memset(temp, 0, 255);
            memcpy(temp, &messageWithoutMSG[1], (size_t)(posOfNewlines[0] - 2));
            printf("%s", temp);
            str_overwrite_stdout();
          }
          else
          {
            char temp[255];
            memset(temp, 0, 255);
            memcpy(temp, &message[posOfNewlines[i - 1]], (size_t)(posOfNewlines[i] - posOfNewlines[i - 1] + 1));
            
            char messageWithoutMSG[255];
            memset(messageWithoutMSG, 0, 255);
            int spacesFound = 0;
            for(int i = 0; i < ((int)strlen(temp)); i++)
            {
              if(temp[i] == ' ')
              {
                spacesFound++;
                if(spacesFound == 2)
                {
                  messageWithoutMSG[(int)strlen(messageWithoutMSG)] = ':';
                }
              }

              if(spacesFound > 0)
              {
                messageWithoutMSG[(int)strlen(messageWithoutMSG)] = temp[i];
              }
            }
            memcpy(messageWithoutMSG, &messageWithoutMSG[1], sizeof(messageWithoutMSG));
            printf("%s", messageWithoutMSG);
            str_overwrite_stdout();
          }
        }

        //Perfectly fine implementation for catching netcat and similar client's messages

        /*
        char messageWithoutMSG[255];
        memset(messageWithoutMSG, 0, 255);
        int spacesFound = 0;
        for(int i = 0; i < ((int)strlen(message)); i++)
        {
          if(message[i] == ' ')
          {
            spacesFound++;
            if(spacesFound == 2)
            {
              messageWithoutMSG[(int)strlen(messageWithoutMSG)] = ':';
            }
          }

          if(spacesFound > 0)
          {
            messageWithoutMSG[(int)strlen(messageWithoutMSG)] = message[i];
          }
        }
        memcpy(messageWithoutMSG, &messageWithoutMSG[1], sizeof(messageWithoutMSG));
        printf("%s", messageWithoutMSG);
        str_overwrite_stdout();
        */
      }
    }
  }
}

void send_msg_handler(void *arg)
{
  char message[1000];

  int *socket = (int *)arg;

  while (1)
  {
    char tempMessage[255];
    memset(tempMessage, 0, 255);
    memset(message, 0, 1000);
    fgets(tempMessage, 255, stdin);
    flushinp();
    sprintf(message, "MSG %s", tempMessage);
    if (strcmp(message, "\n") != 0 && strlen(message) <= 238)
    {
      int response = send(*socket, &message, strlen(message), 0);
      if (response == -1)
      {
        printf("Send failed!\n");
        break;
      }
    }
  }
  catch_ctrl_c(2);
}

int main(int argc, char *argv[])
{

  /* Do magic */
  if (argc != 3)
  {
    printf("Usage: %s <ip>:<port> <name> \n", argv[0]);
    exit(1);
  }
  /*
    Read first input, assumes <ip>:<port> syntax, convert into one string (Desthost) and one integer (port). 
     Atm, works only on dotted notation, i.e. IPv4 and DNS. IPv6 does not work if its using ':'. 
  */
  char *hoststring, *portstring, *rest, *org;
  org = strdup(argv[1]);
  rest = argv[1];
  hoststring = strtok_r(rest, ":", &rest);
  portstring = strtok_r(rest, ":", &rest);
  free(org);

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

  if (strlen(argv[2]) < 12)
  {
    reti = regexec(&regularexpression, argv[2], matches, &items, 0);
    if (reti)
    {
      printf("Bad name\n");
      exit(1);
    }
  }
  else
  {
    printf("Name %s too long.\n", argv[2]);
    exit(1);
  }
  regfree(&regularexpression);

  /* Do magic */
  int port = atoi(portstring);
#ifdef DEBUG
  printf("Connected to %s:%d\n", hoststring, port);
#endif

  struct addrinfo hint, *servinfo, *p;
  int rv;
  int clientSock;

  memset(&hint, 0, sizeof(hint));
  hint.ai_family = AF_UNSPEC;
  hint.ai_socktype = SOCK_STREAM;

  if ((rv = getaddrinfo(hoststring, portstring, &hint, &servinfo)) != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }
  for (p = servinfo; p != NULL; p = p->ai_next)
  {
    if ((clientSock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
    {
      printf("Socket creation failed.\n");
      continue;
    }
    int con = connect(clientSock, p->ai_addr, p->ai_addrlen);
    if (con == -1)
    {
      printf("Connection failed!\n");
      exit(1);
    }
    break;
  }

  if (p == NULL)
  {
    fprintf(stderr, "Client failed to create an apporpriate socket.\n");
    freeaddrinfo(servinfo);
    exit(1);
  }

  signal(SIGINT, catch_ctrl_c);

  char buf[255];
  int recieve, response;
  memset(buf, 0, 255);

  recieve = recv(clientSock, &buf, sizeof(buf), 0);
  if (recieve == 0)
  {
    printf("Recieve failed!\n");
  }

  printf("Server protocol: %s", buf);

  if (strcmp(buf, "Hello 1\n") == 0)
  {
    printf("Protocol supported, sending nickname\n");
  }
  else
  {
    printf("Protocol failed!\n");
    exit(1);
  }

  sprintf(NICKname, "NICK %s", argv[2]);
  sprintf(messageName, "MSG %s", argv[2]);
  strcpy(name, argv[2]);

  response = send(clientSock, &NICKname, strlen(NICKname), 0);
  if (response == -1)
  {
    printf("Response failed!\n");
    exit(1);
  }

  memset(buf, 0, 255);
  recieve = recv(clientSock, &buf, sizeof(buf), 0);
  if (recieve == -1)
  {
    printf("Initital Recieve failed!\n");
    exit(1);
  }

  if (strcmp(buf, "OK\n") == 0)
  {
    printf("Name accepted!\n");
  }
  else if (strcmp(buf, "ERROR\n") == 0)
  {
    printf("Error was recieved\n");
    exit(1);
  }
  else
  {
    printf("Something went wrong");
    exit(1);
  }

  pthread_t send_msg_thread;
  if (pthread_create(&send_msg_thread, NULL, (void *)send_msg_handler, (void *)&clientSock) != 0)
  {
    printf("Error!\n");
    exit(1);
  }

  pthread_t recv_msg_thread;
  if (pthread_create(&recv_msg_thread, NULL, (void *)recv_msg_handler, (void *)&clientSock) != 0)
  {
    printf("Error!\n");
    exit(1);
  }

  while (1)
  {
    if (flag)
    {
      memset(buf, 0, 255);
      strcpy(buf, "exit\n");
      if (send(clientSock, &buf, strlen(buf), 0) == -1)
      {
        printf("Last send with exit failed!\n");
      }
      printf("\nBye\n");
      break;
    }
  }

  close(clientSock);
  return 0;
}