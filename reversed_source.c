// program starts from start function (located at bottom)

__int64 __fastcall printf(unsigned __int8 *a1)
{
  __int64 result; // rax

  while ( 1 ) {
    result = *a1;
    if ( !(_BYTE)result )
      break;
    __asm { syscall; LINUX - }
    ++a1;
  }
  return result;
}

__int64 __fastcall printfn(unsigned __int8 *a1)
{
  __int64 result; // rax

  printf(a1);
  result = syscall_write;
  __asm { syscall; LINUX - }
  return result;
}

__int64 __fastcall read_Helper(__int64 a1, signed int length)
{
  char v3; // [rsp+1Bh] [rbp-31h] BYREF
  __int64 v4; // [rsp+1Ch] [rbp-30h]
  __int64 v5; // [rsp+24h] [rbp-28h]
  char *v6; // [rsp+2Ch] [rbp-20h]
  __int64 v7; // [rsp+34h] [rbp-18h]
  __int64 v8; // [rsp+3Ch] [rbp-10h]
  unsigned int i; // [rsp+48h] [rbp-4h]

  for ( i = 0; (int)i < length; ++i ) {
    v8 = syscall_read;                          // 0
    v7 = 0LL;
    v6 = &v3;
    v5 = 1LL;
    __asm { syscall; LINUX - }                  // read(0, v6, 1)
    v4 = syscall_read;
    if ( v3 == '\n' ) {                         // enter
      *(_BYTE *)((int)i + a1) = 0;
      return i;
    }
    *(_BYTE *)(a1 + (int)i) = v3;
  }
  return i;
}

__int64 custom_scanf()
{
  char v1[36]; // [rsp+0h] [rbp-30h] BYREF
  int v2; // [rsp+24h] [rbp-Ch]
  int i; // [rsp+28h] [rbp-8h]
  unsigned int v4; // [rsp+2Ch] [rbp-4h]

  v4 = 0;
  v2 = read_Helper((__int64)v1, 32);
  for ( i = 0; i < v2; ++i ) {
    if ( v1[i] <= 0x2F || v1[i] > 0x39 )        // only '1' ~ '9'
      return 0xFFFFFFFFLL;
    v4 = 10 * v4 + v1[i] - '0';
  }
  return v4;
}

__int64 __fastcall strlen_includeNULL(__int64 a1)
{
  unsigned int i; // [rsp+14h] [rbp-4h]

  for ( i = 0; *(_BYTE *)((int)i + a1); ++i )
    ;
  return i;
}

_BOOL8 __fastcall strcmp(__int64 a1, __int64 a2)
{
  int len_a1; // [rsp+18h] [rbp-8h]
  int i; // [rsp+1Ch] [rbp-4h]

  len_a1 = strlen_includeNULL(a1);
  if ( len_a1 != (unsigned int)strlen_includeNULL(a2) )
    return 0LL;
  for ( i = 0; i < len_a1 && *(_BYTE *)(i + a1) == *(_BYTE *)(i + a2); ++i )
    ;
  return !*(_BYTE *)(i + a1) && !*(_BYTE *)(i + a2) && len_a1 == i;
}

void __noreturn exit()
{
  __asm { syscall; LINUX - }
}

__int64 __fastcall printInt(int a1)
{
  int v1; // eax
  int v2; // eax
  int v3; // eax
  int v5; // [rsp+Ch] [rbp-34h]
  unsigned __int8 v6[35]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int8 v7; // [rsp+33h] [rbp-Dh]
  int v8; // [rsp+34h] [rbp-Ch]
  int i; // [rsp+38h] [rbp-8h]
  int v10; // [rsp+3Ch] [rbp-4h]

  v5 = a1;
  v10 = 0;
  if ( a1 ) {
    if ( a1 < 0 ) {
      v2 = v10++;
      v6[v2] = 45;
      v5 = -a1;
    }
    v8 = v10;
    while ( v5 ) {
      v3 = v10++;
      v6[v3] = (char)v5 % 10 + 48;
      v5 /= 10;
    }
    for ( i = v8; i < v10 / 2; ++i ) {
      v7 = v6[i];
      v6[i] = v6[v10 - i - 1];
      v6[v10 - i - 1] = v7;
    }
  } else {
    v1 = v10++;
    v6[v1] = 48;
  }
  v6[v10] = 0;
  return printf(v6);
}

__int64 __fastcall strstr(__int64 a1, __int64 a2)
{
  int j; // [rsp+18h] [rbp-8h]
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; *(_BYTE *)(i + a1); ++i ) {
    for ( j = 0; *(_BYTE *)(j + a2) && *(_BYTE *)(i + j + a1) == *(_BYTE *)(j + a2); ++j )
      ;
    if ( !*(_BYTE *)(j + a2) )
      return 1LL;
  }
  return 0LL;
}

// (filename, v2, v6)
__int64 open_write_close()
{
  __asm { syscall; LINUX - }
  if ( syscall_open < 0 )
    return 0xFFFFFFFFLL;
  __asm
  {
    syscall; LINUX -
    syscall; LINUX -
  }
  return (unsigned int)syscall_write;
}

// (path, buf, 0x7FFF)
__int64 open_read_close()
{
  __asm { syscall; LINUX - }
  if ( syscall_open < 0 )                       // read only로 path 파일 열기
    return 0xFFFFFFFFLL;
  __asm
  {
    syscall; LINUX -                            // 읽은 내용을 buf에 넣기
    syscall; LINUX -
  }                                             // close
  return (unsigned int)syscall_read;
}

// 1 <= size <= 257 or 32 or 0x7FFF or large
int *__fastcall malloc_guess(int size)
{
  __int64 v2; // [rsp+4h] [rbp-20h]
  signed int aligned_size; // [rsp+10h] [rbp-14h]
  __int64 v4; // [rsp+14h] [rbp-10h]
  __int64 v5; // [rsp+1Ch] [rbp-8h]

  if ( !size )
    return 0LL;
  aligned_size = (size + 15) & 0xFFFFFFF0;
  v5 = first_freed_heap;
  v4 = 0LL;
  while ( 1 ) {
    if ( !v5 )
      return 0LL;
    if ( aligned_size <= *(_DWORD *)v5 )
      break;
    v4 = v5;
    v5 = *(_QWORD *)(v5 + 8);
  }
  if ( *(int *)v5 >= (unsigned __int64)(aligned_size + 16LL) ) {
    v2 = aligned_size + 16LL + v5;
    *(_DWORD *)v2 = *(_DWORD *)v5 - aligned_size - 16;
    *(_QWORD *)(v2 + 8) = *(_QWORD *)(v5 + 8);
    *(_QWORD *)(v5 + 8) = v2;
    *(_DWORD *)v5 = aligned_size;
  }
  if ( v4 )
    *(_QWORD *)(v4 + 8) = *(_QWORD *)(v5 + 8);
  else
    first_freed_heap = *(_QWORD *)(v5 + 8);
  return (int *)(v5 + 16);
}

int *__fastcall free_guess(unsigned __int64 ptr)
{
  int *result; // rax
  unsigned __int64 free_heap_header; // [rsp+18h] [rbp-18h]
  unsigned __int64 prev_heap_header; // [rsp+20h] [rbp-10h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  if ( ptr ) {
    result = (int *)&unk_5000;
    if ( ptr >= (unsigned __int64)&unk_5000 ) {
      result = &syscall_read;
      if ( ptr < (unsigned __int64)&syscall_read ) {
        free_heap_header = ptr - 16;
        v4 = first_freed_heap;
        prev_heap_header = 0LL;
        while ( v4 && v4 < free_heap_header ) {
	        // go to the heap right before the ptr heap
          prev_heap_header = v4;
          v4 = *(_QWORD *)(v4 + 8);
        }
        if ( prev_heap_header ) {
          *(_QWORD *)(free_heap_header + 8) = *(_QWORD *)(prev_heap_header + 8);
          *(_QWORD *)(prev_heap_header + 8) = free_heap_header;
        } else {
	        // modify freed heap, connect previous freed heap
          *(_QWORD *)(free_heap_header + 8) = first_freed_heap;
          first_freed_heap = ptr - 16;
        }
        return (int *)merge_guess();
      }
    }
  }
  return result;
}

__int64 merge_guess()
{
  __int64 result; // rax
  int v1; // [rsp+0h] [rbp-Ch]
  int *heap_header; // [rsp+4h] [rbp-8h]

  result = first_freed_heap;
  heap_header = (int *)first_freed_heap;
  while ( heap_header ) {
    result = *((_QWORD *)heap_header + 1);
    if ( !result )
      break;
    if ( (int *)((char *)heap_header + *heap_header + 16) == *((int **)heap_header + 1) ) {
      *heap_header += **((_DWORD **)heap_header + 1) + 16;
      result = (__int64)heap_header;
      *((_QWORD *)heap_header + 1) = *(_QWORD *)(*((_QWORD *)heap_header + 1) + 8LL);
    } else {
      result = *((_QWORD *)heap_header + 1);
      heap_header = (int *)result;
    }
  }
  if ( heap_header ) {
    v1 = (_DWORD)&unk_10000 - ((char *)heap_header - (char *)&unk_5000);
    result = (unsigned int)*heap_header;
    if ( v1 > (int)result ) {
      result = (__int64)heap_header;
      *heap_header = v1 - 16;
    }
  }
  return result;
}

void *init() {
  void *result; // rax

  first_freed_heap = (__int64)&unk_5000;
  unk_5000 = (_DWORD)&unk_10000;
  result = &unk_5000;
  *((_QWORD *)&unk_5000 + 1) = 0LL;
  return result;
}

__int64 login()
{
  __int64 password; // [rsp+8h] [rbp-18h]
  __int64 name; // [rsp+10h] [rbp-10h]
  int i; // [rsp+1Ch] [rbp-4h]

  printf("Username: ");
  name = malloc_guess(64LL);
  if ( name ) {
    read_Helper(name, 64);
    if ( (unsigned int)strlen_includeNULL(name) ) {
      printf("Password: ");
      password = malloc_guess(64LL);
      if ( password ) {
        read_Helper(password, 64);
        if ( (unsigned int)strlen_includeNULL(password) ) {
          if ( NumUser ) {
            for ( i = 0; i < NumUser; ++i ) {
              if ( (unsigned int)strcmp(**((_QWORD **)&UserInfo_struct_list + i), name)// UserInfo_struct = &name; &password
                && (unsigned int)strcmp(*(_QWORD *)(*((_QWORD *)&UserInfo_struct_list + i) + 8LL), password) ) {
                UserIndex = i;                  // 찾은 User의 index
              }
            }
            if ( UserIndex == -1 )
              printfn((__int64)"Invalid username or password");
            else
              printfn((__int64)"Logged in successfully!");
            free_guess(name);
            return free_guess(password);
          } else {
            return printfn((__int64)"No users registered");
          }
        } else {
          printfn((__int64)"Invalid password");
          free_guess(password);
          return login();
        }
      } else {
        printfn((__int64)"Invalid password");
        free_guess(0LL);
        return login();
      }
    } else {
      printfn((__int64)"Invalid username");
      free_guess(name);
      return login();
    }
  } else {
    printfn((__int64)"Invalid username");
    free_guess(0LL);
    return login();
  }
}

__int64 register()
{
  struct_UserInfo_struct *UserInfo_struct; // [rsp+8h] [rbp-18h]
  int *password; // [rsp+10h] [rbp-10h]
  int *name; // [rsp+18h] [rbp-8h]

  if ( NumUser > 0 )
    return printfn((__int64)"You can only register one account!");
  printf("Username: ");
  name = malloc_guess(32);
  if ( name ) {
    read_Helper((__int64)name, 32);
    if ( (unsigned int)strlen_includeNULL((__int64)name) ) {
      printf("Password: ");
      password = malloc_guess(32);
      if ( password ) {
        read_Helper((__int64)password, 32);
        if ( (unsigned int)strlen_includeNULL((__int64)password) ) {
          UserInfo_struct = (struct_UserInfo_struct *)malloc_guess(0x4010);
          UserInfo_struct->UserName = name;
          UserInfo_struct->PassWord = password;
          UserInfo_struct->strIndex = 0;
          UserInfo_struct_list[NumUser++] = UserInfo_struct;
          return printfn((__int64)"User registered successfully!");
        } else {
          printfn((__int64)"Invalid password");
          free_guess((unsigned __int64)password);
          return register();
        }
      } else {
        printfn((__int64)"Invalid password");
        free_guess(0LL);
        return register();
      }
    } else {
      printfn((__int64)"Invalid username");
      free_guess((unsigned __int64)name);
      return register();
    }
  } else {
    printfn((__int64)"Invalid username");
    free_guess(0LL);
    return register();
  }
}

__int64 AddString()
{
  int *strbuf; // [rsp+0h] [rbp-10h]
  int strlength; // [rsp+Ch] [rbp-4h]

  if ( *(int *)(UserInfo_struct_list[UserIndex] + 16LL) > 2046 )
    return printfn((__int64)"You have reached the maximum number of strings");
  printf("Enter string length: ");
  strlength = custom_scanf();
  if ( strlength > 0 && strlength <= 256 ) {
    printf("Enter a string: ");
    strbuf = malloc_guess(strlength + 1);
    if ( !strbuf ) {
      printfn((__int64)"Failed to allocate memory");
      printfn((__int64)&enter);
      exit();
    }
    read_Helper((__int64)strbuf, strlength + 1);
    *(_QWORD *)(UserInfo_struct_list[UserIndex]
              + 8 * ((int)(*(_DWORD *)(UserInfo_struct_list[UserIndex] + 16LL))++ + 2LL)
              + 8) = strbuf;
    return printfn((__int64)"String added successfully!");
  } else {
    printfn((__int64)"Invalid length");
    return printfn((__int64)&enter);
  }
}

__int64 DelString()
{
  int del_Index; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  if ( *(_DWORD *)(UserInfo_struct_list[UserIndex] + 16LL) ) {
    printf("Enter the index of the string to delete: ");
    del_Index = custom_scanf();
    if ( del_Index >= 0 && del_Index < *(_DWORD *)(UserInfo_struct_list[UserIndex] + 16LL) ) {
      free_guess(*(_QWORD *)(UserInfo_struct_list[UserIndex] + 8 * (del_Index + 2LL) + 8));
      for ( i = del_Index; i < *(_DWORD *)(UserInfo_struct_list[UserIndex] + 16LL) - 1; ++i )
        *(_QWORD *)(UserInfo_struct_list[UserIndex] + 8 * (i + 2LL) + 8) = *(_QWORD *)(UserInfo_struct_list[UserIndex]
                                                                                     + 8 * (i + 1 + 2LL)
                                                                                     + 8);
      --*(_DWORD *)(UserInfo_struct_list[UserIndex] + 16LL);
      return printfn((__int64)"String deleted successfully!");
    } else {
      printfn((__int64)"Invalid index");
      return printfn((__int64)&enter);
    }
  } else {
    printfn((__int64)"No strings to delete");
    return printfn((__int64)&enter);
  }
}

__int64 ViewString()
{
  __int64 result; // rax
  int i; // [rsp+Ch] [rbp-4h]

  if ( *(_DWORD *)(UserInfo_struct_list[UserIndex] + 16LL) ) {
    for ( i = 0; ; ++i ) {
      result = *(unsigned int *)(UserInfo_struct_list[UserIndex] + 16LL);
      if ( i >= (int)result )
        break;
      printf("String ");
      printInt((unsigned int)i);
      printf(": ");
      printfn(*(_QWORD *)(UserInfo_struct_list[UserIndex] + 8 * (i + 2LL) + 8));
    }
  } else {
    printfn((__int64)"No strings to view");
    return printfn((__int64)&enter);
  }
  return result;
}

int *SaveFile()
{
  int v1; // [rsp+8h] [rbp-28h]
  int *buf; // [rsp+10h] [rbp-20h]
  int *filename; // [rsp+18h] [rbp-18h]
  int j; // [rsp+24h] [rbp-Ch]
  int i; // [rsp+28h] [rbp-8h]
  unsigned int v6; // [rsp+2Ch] [rbp-4h]

  printf("Enter the filename: ");
  filename = malloc_guess(32);
  if ( filename
    && (read_Helper((__int64)filename, 32), (unsigned int)strlen_includeNULL((__int64)filename))
    && !(unsigned int)strstr((__int64)filename, (__int64)"flag") ) {
    buf = malloc_guess(0x7FFF);
    if ( !buf ) {
      printfn((__int64)"Failed to allocate memory");
      printfn((__int64)&enter);
      exit();
    }
    v6 = 0;
    for ( i = 0; i < *(_DWORD *)(UserInfo_struct_list[UserIndex] + 16LL); ++i ) {
      v1 = strlen_includeNULL(*(_QWORD *)(UserInfo_struct_list[UserIndex] + 8 * (i + 2LL) + 8));
      for ( j = 0; j < v1; ++j )
        *((_BYTE *)buf + (int)v6++) = *(_BYTE *)(*(_QWORD *)(UserInfo_struct_list[UserIndex] + 8 * (i + 2LL) + 8) + j);
      *((_BYTE *)buf + (int)v6++) = '\n';
    }
    if ( (int)open_write_close(filename, buf, v6) >= 0 )// write string in buf to file filename {
      printfn((__int64)"Strings saved to file successfully!");
      return free_guess((unsigned __int64)buf);
    } else {
      printfn((__int64)"Failed to write file");
      return (int *)printfn((__int64)&enter);
    }
  } else {
    printfn((__int64)"Invalid filename");
    return (int *)printfn((__int64)&enter);
  }
}

int *LoadFile()
{
  int *v1; // [rsp+0h] [rbp-30h]
  int read_length; // [rsp+Ch] [rbp-24h]
  int *buf; // [rsp+10h] [rbp-20h]
  int *path; // [rsp+18h] [rbp-18h]
  int i; // [rsp+20h] [rbp-10h]
  int v6; // [rsp+24h] [rbp-Ch]
  int v7; // [rsp+28h] [rbp-8h]
  int v8; // [rsp+2Ch] [rbp-4h]

  printf("Enter the filename: ");
  path = malloc_guess(32);
  if ( path
    && (read_Helper((__int64)path, 32), (unsigned int)strlen_includeNULL((__int64)path))
    && !(unsigned int)strstr((__int64)path, (__int64)"flag") ) {
    buf = malloc_guess(0x7FFF);
    if ( !buf ) {
      printfn("Failed to allocate memory");
      printfn((unsigned __int8 *)&enter);
      exit();
    }                                           // (path, buf, 0x7FFF)
    read_length = open_read_close();            // 정상적으로 파일 열림 => 읽은 byte 수 / 비정상적 => -1
    if ( read_length >= 0 ) {
      v8 = 0;
      v7 = 0;
      while ( v8 < read_length ) {
        v6 = 0;
        while ( *((_BYTE *)buf + v8) != '\n' ) {
          ++v6;
          ++v8;
        }
        v1 = malloc_guess(v6 + 1);
        if ( !v1 ) {
          printfn("Failed to allocate memory");
          printfn((unsigned __int8 *)&enter);
          exit();
        }
        for ( i = 0; i < v6; ++i )
          *((_BYTE *)v1 + i) = *((_BYTE *)buf + v7++);
        *((_BYTE *)v1 + v6) = 0;
        *(_QWORD *)(UserInfo_struct_list[UserIndex]
                  + 8 * ((int)(*(_DWORD *)(UserInfo_struct_list[UserIndex] + 16LL))++ + 2LL)
                  + 8) = v1;
        ++v8;
        ++v7;
      }
      printfn("Strings loaded from file successfully!");
      return free_guess((unsigned __int64)buf);
    } else {
      printfn("Failed to read file");
      return (int *)printfn((unsigned __int8 *)&enter);
    }
  } else {
    printfn("Invalid filename");
    return (int *)printfn((unsigned __int8 *)&enter);
  }
}

// Program runs from here
void __noreturn start()
{
  int choice_login_reg_exit; // [rsp+8h] [rbp-8h]
  int choice_UserMenu; // [rsp+Ch] [rbp-4h]

  init();
  while ( 1 ) {
    printfn((__int64)"Welcome to String Storage!");
    printfn((__int64)"Please login or register an account to continue :)");
    printfn((__int64)&enter);                   // 개행?
    while ( UserIndex == -1 ) {
      printfn((__int64)"1. Login");
      printfn((__int64)"2. Register");
      printfn((__int64)"3. Exit");
      printf("Choose an option: ");
      choice_login_reg_exit = custom_scanf();
      printfn((__int64)&enter);                 // 개행?
      if ( choice_login_reg_exit == 1 ) {
        login();
      } else if ( choice_login_reg_exit == 2 ) {
        register();
      } else {
        if ( choice_login_reg_exit == 3 )
          exit();
        printfn((__int64)"Invalid option");
      }
      printfn((__int64)&enter);
    }
    printf("Welcome to String Storage, ");
    printf(*(unsigned __int8 **)UserInfo_struct_list[UserIndex]);
    printfn((__int64)"!");
    printfn((__int64)&enter);
    while ( 1 ) {
      printfn((__int64)"1. Add string");
      printfn((__int64)"2. Delete string");
      printfn((__int64)"3. View strings");
      printfn((__int64)"4. Save to File");
      printfn((__int64)"5. Load from File");
      printfn((__int64)"6. Logout");
      printf("Choose an option: ");
      choice_UserMenu = custom_scanf();
      printfn((__int64)&enter);
      switch ( choice_UserMenu ) {
        case 1:
          AddString();
          goto LABEL_26;
        case 2:
          DelString();
          goto LABEL_26;
        case 3:
          ViewString();
          goto LABEL_26;
        case 4:
          SaveFile();
          goto LABEL_26;
        case 5:
          LoadFile();
          goto LABEL_26;
      }
      if ( choice_UserMenu == 6 )
        break;
      printfn((__int64)"Invalid option");
LABEL_26:
      printfn((__int64)&enter);
    }
    UserIndex = -1;
  }
}
