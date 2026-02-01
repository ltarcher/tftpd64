//////////////////////////////////////////////////////
//
// Projet TFTPD32.  January 2006 Ph.jounin
// Projet DHCPD32.  January 2006 Ph.jounin
// File bootpd_util.c:    Manage BOOTP/DHCP protocols
//
// source released under European Union Public License
//
//////////////////////////////////////////////////////

#include "headers.h"

#include <stdio.h>          // sscanf is used
#include <process.h>        // endthread + beginthread
#include <iphlpapi.h>		// ARP table management

#include "threading.h"
#include "bootpd_functions.h"

// Static MAC-IP binding storage
struct StaticBinding *tStaticBindings = NULL;
int nStaticBindingCount = 0;



/*
 *
 * Takes an internet address and an optional interface address as
 * arguments and checks their validity.
 * Add the interface number and IP to an MIB_IPNETROW structure
 * and remove the entry from the ARP cache.
 * Code adapted from ReactOS 
 */
int ArpDeleteHost(struct in_addr addr)
{
PMIB_IPNETTABLE pIpNetTable = NULL;
ULONG Size = 0;
DWORD dwIpAddr = 0;
INT iRet;
MIB_IPNETROW DelHost;
DWORD Ark;
char *szIPAddr;

    /* check IP address */
    dwIpAddr = addr.s_addr;

    /* We need the IpNetTable to get the adapter index */
    /* Return required buffer size */
    GetIpNetTable(NULL, &Size, 0);

    /* allocate memory for ARP address table */
    pIpNetTable = (PMIB_IPNETTABLE) calloc (Size, 1);
    if (		pIpNetTable == NULL
		||   (iRet = GetIpNetTable(pIpNetTable, &Size, TRUE)) != NO_ERROR )
        goto cleanup;

     /* we need to read the ARP table in order to get the right interface table */
	for ( Ark=0 ;
		  Ark<pIpNetTable->dwNumEntries && pIpNetTable->table[Ark].dwAddr != dwIpAddr ;
		  Ark++) ;
	if ( Ark<pIpNetTable->dwNumEntries )
	{
        DelHost.dwAddr = dwIpAddr;
        DelHost.dwIndex = pIpNetTable->table[Ark].dwIndex;
		iRet = DeleteIpNetEntry (& DelHost);
		szIPAddr = inet_ntoa (addr);
		if (iRet != NO_ERROR) LOG (5, "IP address %s flushed from ARP table", szIPAddr);
    }

cleanup:
    if (pIpNetTable != NULL) free (pIpNetTable);
    return 0;
} // ArpDeleteHost

/*
 * Searches adapters for the one that has an IP addressed assigned to
 * it that matches szIP. Set the DWORD pointer dwAdapter to the adapter
 * index with the matching IP address. If no matching adapter is found
 * it will be set to 0. Also sets the DWORD pointed to by dwFirstAdapter
 * to the first adapter in the list, or the first adapter that matches
 * the IP address. If either of these pointers are NULL, they won't be
 * set. Returns 0 if no errors occurred.
 * Written by Cengiz Beytas
 */
int FindAdapterIP(char *szIP, DWORD *pdwAdapter, DWORD *pdwFirstAdapter)
{
	PIP_ADAPTER_ADDRESSES pAdapterAddresses, pNext;
	PIP_ADAPTER_UNICAST_ADDRESS pIP;
	struct sockaddr saIP;
	struct addrinfo *pList;
	DWORD dwResult, dwSize, dwIndex, dwFirst;
	int i;
	
	// Set DWORDs to zero for now.
	if (pdwAdapter != NULL) *pdwAdapter = 0;
	if (pdwFirstAdapter != NULL) *pdwFirstAdapter = 0;
	
	// Was an IP address specified?
	if (szIP != NULL)
	{
		// Don't process empty string
		if (szIP[0] != 0)
		{
			// Try to convert IP string
			i = getaddrinfo(szIP, NULL, NULL, &pList);
			if (i != 0) return 1;
			// Copy IP address from addrinfo structure
			memcpy(&saIP, pList->ai_addr, sizeof(saIP));	
		} else memset(&saIP, 0, sizeof(saIP));
	} else memset(&saIP, 0, sizeof(saIP));		

	// Find size of Adapter Addresses list
	pAdapterAddresses = NULL;
	dwSize = 0;
	dwResult = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAdapterAddresses, &dwSize);
	if (dwResult != ERROR_BUFFER_OVERFLOW) return 1;

	// Allocate buffer to hold Adapters Addresses list
	pAdapterAddresses = NULL;
	pAdapterAddresses = (PIP_ADAPTER_ADDRESSES) calloc(1, dwSize);
	if (pAdapterAddresses == NULL) return 1;

	// Get Full Adapter Addresses list
	dwResult = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAdapterAddresses, &dwSize);
	if (dwResult != NO_ERROR)
	{
		free(pAdapterAddresses);
		return 1;
	}

	// Search linked list for iaIP
	pNext = pAdapterAddresses;
	dwFirst = (DWORD)0xFFFFFFFF;
	dwIndex = (DWORD)0xFFFFFFFF;
	while (pNext != NULL)
	{
		// Set first adapter number, if unset
		if (dwFirst == (DWORD)0xFFFFFFFF) dwFirst = pNext->IfIndex;
		// Check this adapter's IP addresses for a match
		pIP = pNext->FirstUnicastAddress;
		// Check all unicast IPs for match
		while (pIP != NULL)
		{
			// Does the IP match?
			if (memcmp(&saIP, pIP->Address.lpSockaddr, sizeof(saIP)) == 0)
			{
				// This adapter's IP address matches
				if (dwIndex == (DWORD)0xFFFFFFFF) dwFirst = pNext->IfIndex;
				dwIndex = pNext->IfIndex;
			}
			pIP = pIP->Next;
		}
		pNext = pNext->Next;
	}

	// Set the DWORD pointer values
	if (pdwAdapter != NULL)
	{
		if (dwIndex == (DWORD)0xFFFFFFFF) *pdwAdapter = 0;
		else *pdwAdapter = dwIndex;
	}
	if (pdwFirstAdapter != NULL)
	{
		if (dwFirst == (DWORD)0xFFFFFFFF) *pdwFirstAdapter = 0;
		else *pdwFirstAdapter = dwFirst;
	}
	
	// Free Buffer Memory
	free(pAdapterAddresses);
	return 0;
} // FindAdapterIP


//////////////////////////////////////////////////////////////////////////////////////////////
// AddOption Translation
// Translates the option values into a value
// Use the SnmpCmd syntax ("a ip @" "s string", "i integer", "x string", "u unsigned")
//////////////////////////////////////////////////////////////////////////////////////////////
int TranslateParam2Value (char *buffer, int len, const char *opt_val, struct in_addr ip, const char *tMac)
{
char sz[256];
const char *p, *q;
int  nIPAddr, nLen, c;
// the number of bytes used by n hexa digit 0xABCDE which has 5 digits will form a 4-byte number)
static const char cvt[] = { 0, 1, 1, 2, 2, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8 };
   if (opt_val[1] == ' ')
   { 
       p = opt_val+2;	// p points on data 
	   switch (opt_val [0])
	   {
			case 'a' : // list of IP address
				for (nIPAddr=0 ;  *p!=0 && nIPAddr*4<len-4; nIPAddr++ ) 
				{
				  * ((unsigned long *) buffer + nIPAddr) = inet_addr (p);
				   while ( *p!=0 &&  (isdigit(*p) || *p=='.') )  p++;  // go to end of address
				   while ( *p!=0 && *p==' ' ) p++;	// skip spaces
				}
				return nIPAddr * sizeof (unsigned long);
			case 's' : // string
					lstrcpyn (sz, p, len);
					TranslateExp (sz, buffer, ip, tMac);
					buffer [len-1] = 0;
					return lstrlen (buffer);
			case 'I' :	// integer 
			    * (unsigned short *) buffer = atoi (p);
				return sizeof (unsigned short);
			case 'i' :	// integer 
			    * (unsigned long *) buffer = atoi (p);
				return sizeof (unsigned long);
			case 'N' :	// integer network order
			    * (unsigned short *) buffer = htons (atoi (p));
				return sizeof (unsigned short);
			case 'n' :	// integer long network order
			    * (unsigned long *) buffer = htonl (atoi (p));
				return sizeof (unsigned long);			
			case 'b' :	// list of 1 (b)yte digits
				for (nLen=0 ;  *p!=0 && nLen<len-1; nLen++ ) 
				{					
					sscanf(p, "%u", & c);  
					buffer [nLen] = (char) c;  
				    while ( *p!=0 && isdigit(*p) ) p++;	// to next digit
 				    while ( *p!=0 && (*p==' ' || *p=='.' || *p==':') ) p++;	// skip spaces
				}
				return nLen;
			case 'x' :	// list of he(x) digits
				for (nLen=0 ;  *p!=0 && nLen<len-8; p = q ) 
				{					
					for ( q = p; isxdigit(*q) ; q++ );  // search next field
					switch (  cvt [ min (q-p, 8) ]  )
					{
						case 1 : sscanf(p, "%x", & c);  buffer [nLen] = (char) c;  break;
						case 2 : sscanf(p, "%hx",  buffer+nLen); break;
						case 4 : sscanf(p, "%lx",  buffer+nLen); break;
						case 8 : sscanf(p, "%llx", buffer+nLen); break;
					}
				   nLen += cvt [min (q-p, 8)] ;
				   while ( *q!=0 && (*q==' ' || *q=='.' || *q==':') ) q++;	// skip spaces
				}
				return nLen;
	   } // switch opt_val[0]
   }
   // non trouve --> conserver la chaine
	lstrcpyn (sz, opt_val, len);
	TranslateExp (sz, buffer, ip, tMac);
	( (char *) buffer) [len-1] = 0;
	return lstrlen (buffer);
} // TranslateParam2Value




///////////////////////////////////////////
//  DHCP configuration management
///////////////////////////////////////////

// The data to translate the registry entries into the sParamDHCP struct
// DHCP parameters in configuration file or registry
static struct
{
   char *szEntry;
   void *pValue;
   int   nType;
   int   nBufSize;
}
tDHCPd32Entry[] =
{
    KEY_DHCP_POOL,        sParamDHCP.szAddr ,          REG_SZ,    sizeof sParamDHCP.szAddr,
    KEY_DHCP_POOLSIZE,  & sParamDHCP.nPoolSize,        REG_DWORD, sizeof sParamDHCP.nPoolSize,
    KEY_DHCP_BOOTFILE,    sParamDHCP.szBootFile,       REG_SZ,    sizeof sParamDHCP.szBootFile,
    KEY_DHCP_UEFI_BOOTFILE, sParamDHCP.szUefiBootFile, REG_SZ, sizeof sParamDHCP.szUefiBootFile,
    KEY_DHCP_DNS,         sParamDHCP.szDns1 ,          REG_SZ,    sizeof sParamDHCP.szDns1,
    KEY_DHCP_DNS2,        sParamDHCP.szDns2 ,          REG_SZ,    sizeof sParamDHCP.szDns2,
    KEY_DHCP_WINS,        sParamDHCP.szWins ,          REG_SZ ,   sizeof sParamDHCP.szWins,
    KEY_DHCP_MASK,        sParamDHCP.szMask ,          REG_SZ ,   sizeof sParamDHCP.szMask,
    KEY_DHCP_DEFROUTER,   sParamDHCP.szGateway,        REG_SZ,    sizeof sParamDHCP.szGateway,
    KEY_DHCP_OPTION42,    sParamDHCP.szOpt42 ,         REG_SZ,    sizeof sParamDHCP.szOpt42,
    KEY_DHCP_OPTION120,   sParamDHCP.szOpt120 ,        REG_SZ,    sizeof sParamDHCP.szOpt120,
    KEY_DHCP_DOMAINNAME,  sParamDHCP.szDomainName,     REG_SZ,    sizeof sParamDHCP.szDomainName,
    KEY_DHCP_LEASE_TIME,& sParamDHCP.nLease,           REG_DWORD, sizeof sParamDHCP.nLease,

}; // tDHCPd32Entry



// Save configuration either in INI file (if it exists) or in registry
int DHCPSaveConfig ( const struct S_DHCP_Param  *pNewParamDHCP )
{
INT   Ark;
char szBuf[64];

     // allocate new array, but keep pointers
     if ( sParamDHCP.nPoolSize!=pNewParamDHCP->nPoolSize )
	 {
         tFirstIP = realloc (tFirstIP, sizeof (tFirstIP[0]) * pNewParamDHCP->nPoolSize);
         tMAC     = realloc (tMAC,     sizeof (tMAC[0]) * pNewParamDHCP->nPoolSize);
		      // do not complain if pool is empty
         if (pNewParamDHCP->nPoolSize!=0 && (tFirstIP==NULL || tMAC==NULL) )
		{
			SVC_ERROR ("Can not allocate memory");
			return FALSE;
		}
	 }
     
     nAllocatedIP = min (nAllocatedIP, pNewParamDHCP->nPoolSize);

     sParamDHCP = *pNewParamDHCP;

     for (Ark=0 ; Ark<SizeOfTab (tDHCPd32Entry) ; Ark++)
        AsyncSaveKey (  TFTPD32_DHCP_KEY,
                        tDHCPd32Entry [Ark].szEntry,
                        tDHCPd32Entry [Ark].pValue,
                        tDHCPd32Entry [Ark].nBufSize,
                        tDHCPd32Entry [Ark].nType,
                        szTftpd32IniFile );
 
 // custom items
    for (Ark=0 ; Ark < SizeOfTab (sParamDHCP.t) ; Ark++)
    {
       wsprintf (szBuf, "%s%d", KEY_DHCP_USER_OPTION_NB, Ark+1);
       AsyncSaveKey  (TFTPD32_DHCP_KEY, szBuf, & sParamDHCP.t[Ark].nAddOption,
                 sizeof sParamDHCP.t[Ark].nAddOption, REG_DWORD, szTftpd32IniFile);
       wsprintf (szBuf, "%s%d", KEY_DHCP_USER_OPTION_VALUE, Ark+1);
       AsyncSaveKey  (TFTPD32_DHCP_KEY,  szBuf, sParamDHCP.t[Ark].szAddOption,
                 sizeof sParamDHCP.t[Ark].szAddOption, REG_SZ, szTftpd32IniFile);
    }

return TRUE;
} // DHCPSaveConfig

// read configuration either from INI file (if it exists) or from the registry
int DHCPReadConfig ( )
{
int   Ark;
char szBuf[128];

   memset (& sParamDHCP, 0, sizeof sParamDHCP);
   sParamDHCP.nLease = DHCP_DEFAULT_LEASE_TIME;

   for (Ark=0 ; Ark<SizeOfTab (tDHCPd32Entry) ; Ark++)
        ReadKey (  TFTPD32_DHCP_KEY, 
                   tDHCPd32Entry [Ark].szEntry,
                   tDHCPd32Entry [Ark].pValue,
                   tDHCPd32Entry [Ark].nBufSize,
                   tDHCPd32Entry [Ark].nType,
                   szTftpd32IniFile );
    // custom items
   for (Ark=0 ; Ark < SizeOfTab (sParamDHCP.t) ; Ark++)
   {
      wsprintf (szBuf, "%s%d", KEY_DHCP_USER_OPTION_NB, Ark+1);
      ReadKey  (TFTPD32_DHCP_KEY, szBuf, & sParamDHCP.t[Ark].nAddOption, 
                sizeof sParamDHCP.t[Ark].nAddOption, REG_DWORD, szTftpd32IniFile);

       wsprintf (szBuf, "%s%d", KEY_DHCP_USER_OPTION_VALUE, Ark+1);
       ReadKey  (TFTPD32_DHCP_KEY,  szBuf, sParamDHCP.t[Ark].szAddOption, 
                 sizeof sParamDHCP.t[Ark].szAddOption, REG_SZ, szTftpd32IniFile);
   }

   if ( sParamDHCP.nPoolSize!=0 )
   {
	  tFirstIP = malloc (sParamDHCP.nPoolSize * sizeof *tFirstIP[0]) ;
	  tMAC = malloc (sParamDHCP.nPoolSize * sizeof *tMAC[0]) ; 
	  if (tFirstIP == NULL  ||  tMAC == NULL ) 
	   {
			SVC_ERROR ("Can not allocate memory");
			return FALSE;
	   }
	   LoadLeases ();
	   LoadStaticBindings ();
	   }
	
	   if (sParamDHCP.nLease==0)
	  {
	     sParamDHCP.nLease=DHCP_DEFAULT_LEASE_TIME;
	     LOG (12, "Lease time not specified, set to 2 days");
	  }
   // compatability 3 -> 4
   if (sParamDHCP.szWins[0]==0  && sParamDHCP.szDns1[0]!=0)
   {
      lstrcpy (sParamDHCP.szWins, sParamDHCP.szDns1);
      LOG (0, "WINS server copied from DNS servers");
   }

return TRUE;
} // DHCPReadConfig


///////////////////////////////////////////
//  translation
///////////////////////////////////////////
// translate $IP$, $MAC$, $ARCH$, and $BootFileName$ keywords
char *TranslateExpEx (const char *exp, char *to, struct in_addr ip, const char *tMac, unsigned char *pDhcpOptions)
{
char *q;
size_t  Ark;
char sz [256];		// somewhat larger that DHCP_FILE_LEN (128 bytes)
unsigned short nArchId;
const char *pszArch;

	// truncate input
	Ark = strnlen ( to, DHCP_FILE_LEN -1 );  	to [Ark] = 0;

// LOG (1, "bootp file fmt is <%s>\n", exp);
// LOG (1, "rqst file is <%s>\n", to);
// LOG (1, "IP <%s>\n", inet_ntoa (ip));
// LOG (1, "MAC is <%s>\n", haddrtoa (tMac, 6, '.'));

    // Check for $ARCH$ variable - detect client architecture
    if ( (q=strstr (exp, "$ARCH$")) != NULL )
    {
       // Search for DHCP Option 93 (PXE Client Architecture ID)
       pszArch = "bios";  // Default to BIOS
       
       if (pDhcpOptions != NULL)
       {
           // Simple search for Option 93
           // Format: 93 [length] [2 bytes arch id]
           unsigned char *p = pDhcpOptions + 4; // Skip magic cookie
           while (*p != DHO_END && p < pDhcpOptions + DHCP_OPTION_LEN - 3)
           {
               if (*p == DHO_PAD)
               {
                   p++;
               }
               else if (*p == DHO_PXE_CLIENT_ARCH_ID && p[1] == 2)
               {
                   nArchId = ntohs(*(unsigned short*)(p + 2));
                   
                   // Map architecture ID to string
                   switch (nArchId)
                   {
                       case 0x0000:  // Intel x86 PC - Legacy BIOS
                           pszArch = "bios";
                           break;
                       case 0x0006:  // EFI IA32 - UEFI 32-bit
                           pszArch = "efi32";
                           break;
                       case 0x0007:  // EFI BC - UEFI Bytecode (64-bit)
                           pszArch = "efi64";
                           break;
                       case 0x0009:  // EFI Xscale
                           pszArch = "efi64";
                           break;
                       case 0x000a:  // EFI IA64
                           pszArch = "efi64";
                           break;
                       case 0x000b:  // ARM 32-bit
                           pszArch = "arm";
                           break;
                       case 0x000d:  // ARM 64-bit
                           pszArch = "arm64";
                           break;
                       case 0x000e:  // RISC-V 32-bit
                           pszArch = "riscv32";
                           break;
                       case 0x000f:  // RISC-V 64-bit
                           pszArch = "riscv64";
                           break;
                       default:
                           pszArch = "bios";  // Fallback to BIOS
                           break;
                   }
                   break;
               }
               else
               {
                   p += 2 + p[1];
               }
           }
       }
       
       lstrcpyn (sz, exp, 1 + (int) (q - exp) );
       lstrcat (sz, pszArch);
       lstrcat (sz, q + sizeof "$ARCH$" - 1);
       lstrcpyn (to, sz, DHCP_FILE_LEN - 1);
    }
    else if ( (q=strstr (exp, "$IP$")) != NULL )
    {
       lstrcpyn (sz, exp, 1 + (int) (q - exp) );
       lstrcat (sz, inet_ntoa (ip) );
       lstrcat (sz, q + sizeof "$IP$" - 1);
       lstrcpyn (to, sz, DHCP_FILE_LEN - 1);
    }
    else if ( (q=strstr (exp, "$MAC$")) != NULL )
    {
       lstrcpyn (sz, exp, 1 + (int) (q - exp) );
       lstrcat (sz, haddrtoa (tMac, 6, '.') );
       lstrcat (sz, q + sizeof "$MAC$" - 1);
       lstrcpyn (to, sz, DHCP_FILE_LEN - 1);
    }
    else if ( (q=strstr (exp, "$BootFileName$")) != NULL )
    {
	   lstrcpyn (sz, exp, 1 + (int) (q - exp) );
	   lstrcat (sz, to);
       lstrcat (sz, q + sizeof "$BootFileName$" - 1);
	   // replace to now
       lstrcpyn (to, sz, DHCP_FILE_LEN - 1);
    }
    else lstrcpyn (to, exp, DHCP_FILE_LEN - 1);

    // truncate
    to [DHCP_FILE_LEN-1]=0;
return to;
} // TranslateExpEx

// Legacy TranslateExp function for backward compatibility
char *TranslateExp (const char *exp, char *to, struct in_addr ip, const char *tMac)
{
    return TranslateExpEx(exp, to, ip, tMac, NULL);
} // TranslateExp



///////////////////////////////////////////
//  DHCP database management
///////////////////////////////////////////
// Returns true if the macaddr is empty
int IsMacEmpty(struct LL_IP* pcur)
{
	return (pcur->sMacAddr[0] == 0) && (pcur->sMacAddr[1] == 0) && (pcur->sMacAddr[2] == 0) &&
		   (pcur->sMacAddr[3] == 0) && (pcur->sMacAddr[4] == 0) && (pcur->sMacAddr[5] == 0);
}

// Comparison between two struct. Serves to sort Array
int QsortCompare (const void *p1, const void *p2)
{
	DWORD addr1 = ntohl((*(const struct LL_IP**)p1)->dwIP.s_addr);
	DWORD addr2 = ntohl((*(const struct LL_IP**)p2)->dwIP.s_addr);

	if(addr1 < addr2)
		return -1;
	if(addr1 == addr2)
		return 0;
	return 1;
} // QsortCompare

int MACCompare (const void* p1, const void* p2)
{
const struct LL_IP  *ip1 = *(const struct LL_IP **) p1;
const struct LL_IP  *ip2 = *(const struct LL_IP **) p2;

return memcmp(ip1->sMacAddr, ip2->sMacAddr, 6);
}

//Increment the number of allocated entries
void IncNumAllocated()
{
   ++nAllocatedIP;
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, KEY_LEASE_NUMLEASES, &nAllocatedIP, sizeof(nAllocatedIP), REG_DWORD, szTftpd32IniFile);
}

//Decrement the number of allocated entries
void DecNumAllocated()
{
   --nAllocatedIP;
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, KEY_LEASE_NUMLEASES, &nAllocatedIP, sizeof(nAllocatedIP), REG_DWORD, szTftpd32IniFile);
}

//Set the number of allocated entries explicitly
void SetNumAllocated(int n)
{
   nAllocatedIP = n;
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, KEY_LEASE_NUMLEASES, &nAllocatedIP, sizeof(nAllocatedIP), REG_DWORD, szTftpd32IniFile);
}

//Set the IP address to a new one
void SetIP(struct LL_IP* pCur, DWORD newip)
{
   char* addr;
   char key [_MAX_PATH];
   sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, pCur->dwAllocNum, KEY_LEASE_IP);
   
   pCur->dwIP.s_addr = newip;
   addr = inet_ntoa(pCur->dwIP);
   // fixed proposed by Colin : change is not saved into ini file
   // if (sSettings.bPersLeases)
   //   AsyncSaveKey(TFTPD32_DHCP_KEY, key, addr, strlen(addr), REG_SZ, szTftpd32IniFile);
}

//Set the MAC address to a new one
void SetMacAddr(struct LL_IP* pCur, const unsigned char *pMac, int nMacLen)
{
   char key [_MAX_PATH];
   char* macaddr;
   sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, pCur->dwAllocNum, KEY_LEASE_MAC);

   memset(pCur->sMacAddr, 0, sizeof pCur->sMacAddr);
   memcpy(pCur->sMacAddr, pMac, min (sizeof pCur->sMacAddr, nMacLen));
   macaddr = haddrtoa(pCur->sMacAddr, 6, ':');
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, key, macaddr, strlen(macaddr), REG_SZ, szTftpd32IniFile);
}

//Set the MAC address to all zeros
void ZeroMacAddr(struct LL_IP* pCur)
{
   char key [_MAX_PATH];
   char* macaddr;
   sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, pCur->dwAllocNum, KEY_LEASE_MAC);

   memset(pCur->sMacAddr, 0, sizeof pCur->sMacAddr);
   macaddr = haddrtoa(pCur->sMacAddr, 6, ':');
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, key, macaddr, strlen(macaddr), REG_SZ, szTftpd32IniFile);
}

//Set tAllocated to the current time
void SetAllocTime(struct LL_IP* pCur)
{
   char* t;
   char key [_MAX_PATH];
   sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, pCur->dwAllocNum, KEY_LEASE_ALLOC);

   time(&pCur->tAllocated);
   t = timetoa(pCur->tAllocated);
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, key, t, strlen(t)+1, REG_SZ, szTftpd32IniFile);
}

//Zero tAllocated
void ZeroAllocTime(struct LL_IP* pCur)
{
   char* t;
   char key [_MAX_PATH];
   sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, pCur->dwAllocNum, KEY_LEASE_ALLOC);

   pCur->tAllocated = 0;
   t = timetoa(pCur->tAllocated);
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, key, t, strlen(t) + 1, REG_SZ, szTftpd32IniFile);
}

//Set tRenewed to the current time
void SetRenewTime(struct LL_IP* pCur)
{
   char* t;
   char key [_MAX_PATH];
   sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, pCur->dwAllocNum, KEY_LEASE_RENEW);

   time(&pCur->tRenewed);
   t = timetoa(pCur->tRenewed);
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, key, t, strlen(t) + 1, REG_SZ, szTftpd32IniFile);
}

//Force tRenewed to a specific time
void ForceRenewTime(struct LL_IP* pCur, time_t newtime)
{
   char* t;
   char key [_MAX_PATH];
   sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, pCur->dwAllocNum, KEY_LEASE_RENEW);

   pCur->tRenewed = newtime;
   t = timetoa(pCur->tRenewed);
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, key, t, strlen(t) + 1, REG_SZ, szTftpd32IniFile);
}

//Zero tRenewed
void ZeroRenewTime(struct LL_IP* pCur)
{
   char* t;
   char key [_MAX_PATH];
   sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, pCur->dwAllocNum, KEY_LEASE_RENEW);

   pCur->tRenewed = 0;
   t = timetoa(pCur->tRenewed);
   if (sSettings.bPersLeases)
      AsyncSaveKey(TFTPD32_DHCP_KEY, key, t, strlen(t) + 1, REG_SZ, szTftpd32IniFile);
}

//Completely renumbers and rewrites the lease list from current membory.  
void ReorderLeases()
{
   int i;
   AsyncSaveKey (TFTPD32_DHCP_KEY, 
				 KEY_LEASE_NUMLEASES, 
				 & nAllocatedIP, 
				 sizeof(nAllocatedIP), 
				 REG_DWORD, 
				 szTftpd32IniFile);

   for(i = 0; i < nAllocatedIP; ++i)
   {
      char key [_MAX_PATH];
      char* macaddr = haddrtoa(tFirstIP[i]->sMacAddr, 6, ':');
      char* addr = inet_ntoa(tFirstIP[i]->dwIP);
      char* alloc = timetoa(tFirstIP[i]->tAllocated);
      char* renew = timetoa(tFirstIP[i]->tRenewed);

      tFirstIP[i]->dwAllocNum = i;
      if (sSettings.bPersLeases)
	  {
		sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, i, KEY_LEASE_MAC);
		SaveKey(TFTPD32_DHCP_KEY, key, macaddr, strlen(macaddr) + 1, REG_SZ, szTftpd32IniFile);
		  sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, i, KEY_LEASE_IP);
		  SaveKey(TFTPD32_DHCP_KEY, key, addr, strlen(addr) + 1, REG_SZ, szTftpd32IniFile);
		  sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, i, KEY_LEASE_ALLOC);
		  SaveKey(TFTPD32_DHCP_KEY, key, alloc, strlen(alloc) + 1, REG_SZ, szTftpd32IniFile);
		  sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, i, KEY_LEASE_RENEW);
         AsyncSaveKey(TFTPD32_DHCP_KEY, key, renew, strlen(renew) + 1, REG_SZ, szTftpd32IniFile);
	  }
   }
}

//Read in and initialize the leases
void LoadLeases(void)
{
   //We need to make sure the leases we load actually fit in the address pool, so we'll be
   //tracking the index to the lease file and the index to the allocated list
   int leaseindex, allocindex;
 
   // From Nick : I realized that there was a race condition in that code, 
   // particularly with the reading and saving of KEY_LEASE_NUMLEASES
   // I�ve added a function, which LoadLeases calls immediately on entry:
   WaitForMsgQueueToFinish (LL_ID_SETTINGS);

   nAllocatedIP = 0;
   ReadKey(TFTPD32_DHCP_KEY, KEY_LEASE_NUMLEASES, &nAllocatedIP, sizeof(nAllocatedIP), REG_DWORD, szTftpd32IniFile);

   if (nAllocatedIP > sParamDHCP.nPoolSize)
   {
      SVC_WARNING ("The pool size is too small for the number of leases, ignoring extra leases");
      nAllocatedIP = sParamDHCP.nPoolSize;
   }

   allocindex = 0;
   for(leaseindex = 0; leaseindex < nAllocatedIP; ++leaseindex)
   {
     char key [_MAX_PATH];
     char tmpval [_MAX_PATH];

     tFirstIP[allocindex] = malloc (sizeof(struct LL_IP));
     memset(tFirstIP[allocindex], 0, sizeof(struct LL_IP));

     tFirstIP[allocindex]->dwAllocNum = leaseindex;
     sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, leaseindex, KEY_LEASE_MAC);
     if(ReadKey(TFTPD32_DHCP_KEY, key, tmpval, _MAX_PATH, REG_SZ, szTftpd32IniFile))
        atohaddr(tmpval, tFirstIP[allocindex]->sMacAddr, 6);
     sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, leaseindex, KEY_LEASE_IP);
     if(ReadKey(TFTPD32_DHCP_KEY, key, tmpval, _MAX_PATH, REG_SZ, szTftpd32IniFile))
        tFirstIP[allocindex]->dwIP.s_addr = inet_addr(tmpval);
     sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, leaseindex, KEY_LEASE_ALLOC);
     if(ReadKey(TFTPD32_DHCP_KEY, key, tmpval, _MAX_PATH, REG_SZ, szTftpd32IniFile))     
        tFirstIP[allocindex]->tAllocated = atotime(tmpval);
     sprintf(key, "%s%d%s", KEY_LEASE_PREFIX, leaseindex, KEY_LEASE_RENEW);
     if(ReadKey(TFTPD32_DHCP_KEY, key, tmpval, _MAX_PATH, REG_SZ, szTftpd32IniFile))
        tFirstIP[allocindex]->tRenewed = atotime(tmpval);

    // fix errors in date conversion (registry modified at hand)
    if (tFirstIP[allocindex]->tAllocated == -1) tFirstIP[allocindex]->tAllocated = 0;
    if (tFirstIP[allocindex]->tRenewed   == -1) tFirstIP[allocindex]->tRenewed   = 0;

     //If the address doesn't fit in the pool, don't add it after all
	 //Since we are assuming the leases were written in order, do a quick check for dups
	 //and invalid macaddrs
     if((!AddrFitsPool(&tFirstIP[allocindex]->dwIP)) || (IsMacEmpty(tFirstIP[allocindex])) ||
		((allocindex > 0) && (tFirstIP[allocindex]->dwIP.s_addr == tFirstIP[allocindex - 1]->dwIP.s_addr)))
     {
        free(tFirstIP[allocindex]);
        tFirstIP[allocindex] = NULL;
     }
     else
	 {
		tMAC[allocindex] = tFirstIP[allocindex];  //Copy to cross index
        ++allocindex;   //Move on to the next one
	 }
   }

   if(allocindex != nAllocatedIP)
      SetNumAllocated(allocindex);

    // ensure that data base is sorted (especially if we've dropped some leases in the load)
    qsort (tMAC, nAllocatedIP, sizeof *tMAC, MACCompare);
    qsort (tFirstIP, nAllocatedIP, sizeof *tFirstIP, QsortCompare);
    ReorderLeases();

} // LoadLeases

/**
 * 比较静态绑定数组两个元素的IP地址（用于qsort）
 */
static int StaticBindingCompare(const void *p1, const void *p2)
{
    DWORD addr1 = ntohl(((const struct StaticBinding*)p1)->dwIP);
    DWORD addr2 = ntohl(((const struct StaticBinding*)p2)->dwIP);
    
    if (addr1 < addr2) return -1;
    if (addr1 > addr2) return 1;
    return 0;
}

/**
 * 检查字符串是否为有效的MAC地址格式（XX:XX:XX:XX:XX:XX）
 */
static BOOL IsValidMacAddressFormat(const char *str)
{
    int i, colonCount = 0;
    
    if (strlen(str) != 17)  // AA:BB:CC:DD:EE:FF 正好17个字符
        return FALSE;
    
    for (i = 0; i < 17; i++)
    {
        if (i % 3 == 2)  // 位置 2, 5, 8, 11, 14 应该是冒号
        {
            if (str[i] != ':')
                return FALSE;
            colonCount++;
        }
        else  // 其他位置应该是十六进制字符
        {
            if (!isxdigit(str[i]))
                return FALSE;
        }
    }
    
    return colonCount == 5;
}

/**
 * 加载所有静态MAC-IP绑定到内存
 * 从注册表/INI文件中读取所有MAC地址键，过滤出MAC格式键并加载对应IP值
 * 返回加载的静态绑定数量
 */
DWORD LoadStaticBindings(void)
{
    HKEY hKey;
    DWORD dwResult;
    char szKeyName[256];
    char szValue[64];
    char *szConfigSource;
    DWORD dwKeyNameSize, dwValueSize, dwValueType;
    DWORD dwIP;
    int nCapacity = 0;
    int i;
    
    LOG(10, "=== Loading static MAC-IP bindings from storage ===");
    
    // 首先释放旧的绑定（如果存在）
    FreeStaticBindings();
    
    // 确定配置存储介质
    if (szTftpd32IniFile[0] != 0)
    {
        // 从 INI 文件加载静态绑定
        // 注意：ReadKey 函数在找到INI键后仍返回0，这里需要直接解析INI文件
        // 提取 section 名称（TFTPD32_DHCP_KEY 格式为 "SOFTWARE\\TFTPD32\\DHCP"，section 为 "DHCP"）
        char szSection[64];
        char szAllKeys[8192];  // 用于存储所有键名的缓冲区
        char *pKey;
        const char *pLastBackslash;
        
        // 从 TFTPD32_DHCP_KEY 中提取最后的 section 名称
        pLastBackslash = strrchr(TFTPD32_DHCP_KEY, '\\');
        if (pLastBackslash != NULL)
        {
            lstrcpyn(szSection, pLastBackslash + 1, sizeof(szSection));
        }
        else
        {
            lstrcpyn(szSection, TFTPD32_DHCP_KEY, sizeof(szSection));
        }
        
        szConfigSource = szTftpd32IniFile;
        LOG(10, "Configuration source: INI file %s, Section: %s", szConfigSource, szSection);
        
        // 使用 GetPrivateProfileStringA 枚举 INI 文件中的所有键
        dwResult = GetPrivateProfileStringA(szSection, NULL, NULL, szAllKeys, sizeof(szAllKeys), szTftpd32IniFile);
        
        if (dwResult == 0 || szAllKeys[0] == '\0')
        {
            LOG(10, "No keys found in INI section [%s]", szSection);
            // 尝试从注册表读取
            goto TryRegistry;
        }
        
        LOG(10, "Found %d bytes of key names in section [%s]", dwResult, szSection);
        
        // 遍历所有键名（由空字符分隔，以双空字符结尾）
        nStaticBindingCount = 0;
        nCapacity = 32;  // 初始容量
        tStaticBindings = (struct StaticBinding*)calloc(nCapacity, sizeof(struct StaticBinding));
        
        if (tStaticBindings == NULL)
        {
            LOG(1, "Failed to allocate memory for static bindings");
            return 0;
        }
        
        for (pKey = szAllKeys; *pKey != '\0'; pKey += strlen(pKey) + 1)
        {
            // 检查是否为 MAC 地址格式的键
            if (!IsValidMacAddressFormat(pKey))
            {
                LOG(12, "Skipping non-MAC key: %s", pKey);
                continue;
            }
            
            // 读取该键的值（IP地址）
            GetPrivateProfileStringA(szSection, pKey, "", szValue, sizeof(szValue), szTftpd32IniFile);
            
            if (szValue[0] == '\0')
            {
                LOG(12, "Skipping MAC key %s with empty value", pKey);
                continue;
            }
            
            // 验证并转换IP地址
            dwIP = inet_addr(szValue);
            if (dwIP == INADDR_NONE || dwIP == 0)
            {
                LOG(1, "Invalid IP address '%s' for MAC %s, skipping", szValue, pKey);
                continue;
            }
            
            // 扩展数组容量（如需要）
            if (nStaticBindingCount >= nCapacity)
            {
                int nNewCapacity = nCapacity * 2;
                struct StaticBinding *pTemp;
                
                pTemp = (struct StaticBinding*)realloc(tStaticBindings, nNewCapacity * sizeof(struct StaticBinding));
                if (pTemp == NULL)
                {
                    LOG(1, "Failed to expand static bindings array");
                    FreeStaticBindings();
                    return 0;
                }
                
                tStaticBindings = pTemp;
                nCapacity = nNewCapacity;
                LOG(5, "Expanded static bindings array to capacity %d", nCapacity);
            }
            
            // 解析并存储MAC地址
            atohaddr(pKey, tStaticBindings[nStaticBindingCount].sMac, 6);
            tStaticBindings[nStaticBindingCount].dwIP = dwIP;
            
            LOG(5, "[INI] %d. Loaded binding: MAC=%s -> IP=%s",
                 nStaticBindingCount + 1, pKey, szValue);
            
            nStaticBindingCount++;
        }
        
        // 打印已加载的绑定摘要
        if (nStaticBindingCount > 0)
        {
            LOG(0, "=== Summary: Loaded %d static MAC-IP bindings from INI file ===", nStaticBindingCount);
            goto Sorting;
        }
        else
        {
            LOG(0, "No static bindings found in INI file, trying registry...");
            FreeStaticBindings();
        }
    }
    
    // 从注册表加载静态绑定（INI文件为空或不存在时）
TryRegistry:
    szConfigSource = "Registry";
    LOG(10, "Loading static bindings from Registry: %s", TFTPD32_DHCP_KEY);
    
    // 打开DHCP注册表键
    dwResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, TFTPD32_DHCP_KEY, 0, KEY_READ, &hKey);
    
    if (dwResult != ERROR_SUCCESS)
    {
        LOG(10, "Failed to open DHCP registry key for static bindings (error %d)", dwResult);
        LOG(0, "No configuration source found for static bindings");
        return 0;
    }
    
    // 初始化容量
    nCapacity = 32;
    tStaticBindings = (struct StaticBinding*)calloc(nCapacity, sizeof(struct StaticBinding));
    
    if (tStaticBindings == NULL)
    {
        LOG(1, "Failed to allocate memory for static bindings");
        RegCloseKey(hKey);
        return 0;
    }
    
    LOG(10, "Enumerating registry values in: %s", TFTPD32_DHCP_KEY);
    
    // 枚举所有注册表值，寻找MAC地址格式的键
    nStaticBindingCount = 0;
    dwResult = ERROR_SUCCESS;
    while (dwResult == ERROR_SUCCESS)
    {
        dwKeyNameSize = sizeof(szKeyName) - 1;
        dwValueSize = sizeof(szValue) - 1;
        dwValueType = REG_SZ;
        
        dwResult = RegEnumValueA(hKey, nStaticBindingCount, szKeyName, &dwKeyNameSize,
                                NULL, &dwValueType, (LPBYTE)szValue, &dwValueSize);
        
        if (dwResult == ERROR_NO_MORE_ITEMS)
        {
            break;  // 枚举完成
        }
        
        if (dwResult != ERROR_SUCCESS)
        {
            LOG(1, "Error enumerating registry value at index %d", nStaticBindingCount);
            continue;
        }
        
        // 只处理字符串类型的值
        if (dwValueType != REG_SZ)
        {
            continue;
        }
        
        // 只处理MAC格式的键（跳过系统键如IP_Pool、PoolSize等）
        if (IsValidMacAddressFormat(szKeyName))
        {
            LOG(5, "Found MAC key in registry: %s -> %s", szKeyName, szValue);
            
            // 验证值是否为有效的IP地址
            dwIP = inet_addr(szValue);
            if (dwIP == INADDR_NONE || dwIP == 0)
            {
                LOG(1, "Invalid IP address '%s' for MAC %s, skipping", szValue, szKeyName);
                continue;
            }
            
            // 扩容（如需要）
            if (nStaticBindingCount >= nCapacity)
            {
                int nNewCapacity = nCapacity * 2;
                struct StaticBinding *pTemp;
                
                pTemp = (struct StaticBinding*)realloc(tStaticBindings, nNewCapacity * sizeof(struct StaticBinding));
                if (pTemp == NULL)
                {
                    LOG(1, "Failed to expand static bindings array");
                    RegCloseKey(hKey);
                    FreeStaticBindings();
                    return 0;
                }
                
                tStaticBindings = pTemp;
                nCapacity = nNewCapacity;
                LOG(5, "Expanded static bindings array to capacity %d", nCapacity);
            }
            
            // 解析MAC地址并存储绑定
            atohaddr(szKeyName, tStaticBindings[nStaticBindingCount].sMac, 6);
            tStaticBindings[nStaticBindingCount].dwIP = dwIP;
            
            LOG(5, "[REG] %d. Loaded binding: MAC=%s -> IP=%s",
                 nStaticBindingCount + 1, szKeyName, szValue);
            
            nStaticBindingCount++;
        }
    }
    
    RegCloseKey(hKey);
    
Sorting:
    // 对静态绑定数组按IP排序，以便快速查找
    if (nStaticBindingCount > 1)
    {
        qsort(tStaticBindings, nStaticBindingCount,
              sizeof(struct StaticBinding), StaticBindingCompare);
        LOG(5, "Sorted %d static bindings by IP address", nStaticBindingCount);
    }
    
    // 打印加载的静态绑定列表摘要
    LOG(0, "=== Summary: Loaded %d static MAC-IP bindings from %s ===",
         nStaticBindingCount, szConfigSource);
    return nStaticBindingCount;
} // LoadStaticBindings

/**
 * 释放静态绑定占用的内存
 */
void FreeStaticBindings(void)
{
    if (tStaticBindings != NULL)
    {
        free(tStaticBindings);
        tStaticBindings = NULL;
    }
    nStaticBindingCount = 0;
    LOG(5, "Freed static bindings memory");
} // FreeStaticBindings

//Free the Lease memory
void FreeLeases(BOOL freepool)
{
	int Ark;

	//Free the individual elements
	for(Ark = 0; Ark < nAllocatedIP; ++Ark)
	{
		free(tFirstIP[Ark]);
		tFirstIP[Ark] = NULL;
		tMAC[Ark] = NULL;  //Yes, they don't point to the same thing, but we're clearing everyone out.
	}
	if(freepool)
	{
		if(tFirstIP)
		{
			free(tFirstIP);
			tFirstIP = NULL;
		}
		if(tMAC)
		{
			free(tMAC);
			tMAC = NULL;
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Data Base Queries
// Retrieve a DHCP item in the data base 
//////////////////////////////////////////////////////////////////////////////////////////////


// Search in the list by IP
struct LL_IP *DHCPSearchByIP (const struct in_addr *pAddr, BOOL* wasexpired)
{
//	int  Ark;
	struct LL_IP** pArk;
	struct LL_IP key, *pkey;
	time_t expire;
	time(&expire);
	expire -= sParamDHCP.nLease * 60; //Adjust now so there's just a simple compare to tRenewed
	
	key.dwIP.s_addr = pAddr->s_addr;
	pkey = &key;
	pArk = bsearch(&pkey, tFirstIP, nAllocatedIP, sizeof(*tFirstIP), QsortCompare);
	if(pArk)
		*wasexpired = ((*pArk)->tRenewed == 0) || (expire > (*pArk)->tRenewed);
	if(pArk)
		return *pArk;
	return NULL;

#if 0
	for (Ark = 0 ;
		 Ark<nAllocatedIP && ! (tFirstIP[Ark]->dwIP.s_addr==pAddr->s_addr) ;
		 Ark++ );

	if(Ark < nAllocatedIP)
	{
		*wasexpired = (tFirstIP[Ark]->tRenewed==0) || (expire > tFirstIP[Ark]->tRenewed);
		return tFirstIP[Ark];
	}
	return NULL;
#endif
} // DHCPSearchByIP


// Search in the list by Mac Address
struct LL_IP *DHCPSearchByMacAddress (const unsigned char *pMac, int nMacLen)
{
	struct LL_IP** pArk;
	struct LL_IP key, *pkey;

	nMacLen = min (nMacLen, 6);
	memcpy(key.sMacAddr, pMac, nMacLen);
	pkey = &key;
	pArk = bsearch(&pkey, tMAC, nAllocatedIP, sizeof(*tMAC), MACCompare);
	if(pArk)
		return *pArk;
	return NULL;

#if 0
int Ark;
   nMacLen = min (nMacLen, sizeof tFirstIP[0]->sMacAddr);
    for (Ark=0 ;
         Ark<nAllocatedIP && memcmp (tFirstIP[Ark]->sMacAddr, pMac, nMacLen)!=0 ;
         Ark++);
return Ark<nAllocatedIP ? tFirstIP[Ark] : NULL ;
#endif
} // DHCPSearchByMacAddress


/**
 * 使用二分查找检查IP是否在静态绑定表中
 */
static struct StaticBinding* FindStaticBindingByIP(DWORD dwIP)
{
    struct StaticBinding key;
    int low, high, mid;
    DWORD targetIP, midIP;
    
    if (nStaticBindingCount == 0)
        return NULL;
    
    targetIP = ntohl(dwIP);
    
    // 手动实现二分查找
    low = 0;
    high = nStaticBindingCount - 1;
    
    while (low <= high)
    {
        mid = (low + high) / 2;
        midIP = ntohl(tStaticBindings[mid].dwIP);
        
        if (midIP < targetIP)
            low = mid + 1;
        else if (midIP > targetIP)
            high = mid - 1;
        else
            return &tStaticBindings[mid];  // 找到匹配
    }
    
    return NULL;  // 未找到
}

/**
 * 检查指定的 IP 是否被某个 MAC 地址静态绑定
 * 如果该被请求分配的 IP 已经静态绑定给其他 MAC，则返回 TRUE
 *
 * @param dwIP 要检查的 IP 地址（网络字节序）
 * @param pRequestMac 请求分配这个 IP 的 MAC 地址
 * @return TRUE 表示该 IP 被其他 MAC 静态绑定，不应该分配；FALSE 表示可以分配
 *
 * 修改后的版本使用内存中的静态绑定表，可以正确检测所有静态绑定，
 * 无论该 MAC 是否已有租约记录。
 */
BOOL DHCP_IsIPBoundToOtherMac(DWORD dwIP, const unsigned char *pRequestMac)
{
    struct StaticBinding *pBinding;
    
    // 避免检查无效 IP
    if (dwIP == INADDR_ANY || dwIP == INADDR_NONE)
        return FALSE;
    
    LOG(12, "=== DHCP_IsIPBoundToOtherMac ===");
    LOG(12, "Checking IP: %s", inet_ntoa(*(struct in_addr *)&dwIP));
    LOG(12, "Requesting MAC: %s", haddrtoa((unsigned char*)pRequestMac, 6, ':'));
    LOG(12, "Static bindings loaded: %d", nStaticBindingCount);
    
    // 使用静态绑定表进行快速二分查找
    pBinding = FindStaticBindingByIP(dwIP);
    
    if (pBinding != NULL)
    {
        // IP 有静态绑定，检查是否是请求的 MAC
        char szBindMac[32];
        haddrtoa_ex(pBinding->sMac, 6, ':', szBindMac, sizeof(szBindMac));
        LOG(5, "*** STATIC BIND CHECK: IP %s is bound to MAC %s ***",
             inet_ntoa(*(struct in_addr *)&dwIP),
             szBindMac);
        
        if (memcmp(pBinding->sMac, pRequestMac, 6) == 0)
        {
            // 绑定给请求的 MAC，可以分配
            LOG(5, "IP %s is bound to requesting MAC %s (OK)",
                 inet_ntoa(*(struct in_addr *)&dwIP),
                 szBindMac);
            return FALSE;
        }
        else
        {
            // 绑定给其他 MAC，不能分配
            char szReqMac[32];
            haddrtoa_ex((unsigned char*)pRequestMac, 6, ':', szReqMac, sizeof(szReqMac));
            LOG(1, "!!! STATIC BINDING CONFLICT !!!");
            LOG(1, "IP %s is statically bound to MAC %s, "
                    "but requested by MAC %s",
                 inet_ntoa(*(struct in_addr *)&dwIP),
                 szBindMac,
                 szReqMac);
            LOG(1, "REFUSING allocation to maintain static binding.");
            return TRUE;
        }
    }
    
    // IP 没有静态绑定，可以分配
    LOG(12, "IP %s has no static binding, can allocate",
         inet_ntoa(*(struct in_addr *)&dwIP));
    LOG(12, "=== End DHCP_IsIPBoundToOtherMac ===");
    return FALSE;
} // DHCP_IsIPBoundToOtherMac

/**
 * 清除指定 MAC 地址的所有旧分配记录
 * 保留最新的一个记录（优先保留 tRenewed>0 的），删除其他重复记录
 *
 * 此函数用于解决 iPXE 等引导程序在多次 DHCP 请求时
 * 导致同一 MAC 地址占用多个 IP 资源的问题。
 *
 * @param pMac MAC 地址
 * @param nMacLen MAC 地址长度
 * @return 删除的记录数量
 */
int DHCPCleanupOldMacAllocations(const unsigned char *pMac, int nMacLen)
{
    int Ark;
    struct LL_IP *pKeep = NULL;
    time_t tLatestRenewed = 0;
    time_t tLatestAllocated = 0;
    time_t tNow;
    int nFoundCount = 0;
    int nDeleted = 0;  // 记录删除的数量
    
    if (nMacLen < 6 || tMAC == NULL || nAllocatedIP <= 0)
        return NULL;
        
    time(&tNow);
    
    // 1. 扫描所有记录，找出该 MAC 的所有分配
    //    并选择保留最新的那一个（优先 tRenewed，其次 tAllocated）
    LOG(12, "Checking for duplicate MAC allocations: %s", haddrtoa(pMac, nMacLen, ':'));
    
    for (Ark = 0; Ark < nAllocatedIP; Ark++)
    {
        struct LL_IP *pItem = tMAC[Ark];
        
        // 检查是否为空记录
        if (IsMacEmpty(pItem))
            continue;
            
        // 检查是否匹配目标 MAC
        if (memcmp(pItem->sMacAddr, pMac, min(nMacLen, 6)) == 0)
        {
            nFoundCount++;
            
            // 判断是否应该保留这个记录
            if (pItem->tRenewed > tLatestRenewed)
            {
                // 这个记录有更新的 renew 时间，应该保留
                if (pKeep != NULL && pKeep != pItem)
                {
                    time_t age = tNow - pKeep->tRenewed;
                    LOG(5, "Marking older allocation for deletion: IP %s (renewed %ld sec ago)",
                         inet_ntoa(pKeep->dwIP), pKeep->tRenewed ? age : 0);
                }
                tLatestRenewed = pItem->tRenewed;
                pKeep = pItem;
            }
            else if (pItem->tRenewed == 0 && tLatestRenewed == 0)
            {
                // 两个记录都未 renewed，比较分配时间
                if (pItem->tAllocated > tLatestAllocated)
                {
                    if (pKeep != NULL && pKeep != pItem)
                    {
                        time_t age = tNow - pKeep->tAllocated;
                        LOG(5, "Marking older allocation for deletion: IP %s (allocated %ld sec ago)",
                             inet_ntoa(pKeep->dwIP), pKeep->tAllocated ? age : 0);
                    }
                    tLatestAllocated = pItem->tAllocated;
                    pKeep = pItem;
                }
                else
                {
                    // 这是一个旧记录
                    time_t age = pItem->tAllocated ? (tNow - pItem->tAllocated) : 0;
                    LOG(5, "Found duplicate allocation for MAC %s: IP %s (allocated %ld sec ago, not renewed)",
                         haddrtoa(pMac, nMacLen, ':'),
                         inet_ntoa(pItem->dwIP), age);
                }
            }
            else
            {
                // 这是一个旧记录（已 renewed 但时间更早）
                time_t age = pItem->tRenewed ? (tNow - pItem->tRenewed) : 0;
                time_t age_alloc = pItem->tAllocated ? (tNow - pItem->tAllocated) : 0;
                LOG(5, "Found duplicate allocation for MAC %s: IP %s (allocated %ld sec ago, renewed %ld sec ago)",
                     haddrtoa(pMac, nMacLen, ':'),
                     inet_ntoa(pItem->dwIP), age_alloc, age);
            }
        }
    }
    
    // 如果没有找到该 MAC 的记录，直接返回
    if (nFoundCount == 0)
    {
        return NULL;
    }
    
    if (nFoundCount > 1)
    {
        LOG(5, "Found %d duplicate IP allocations for MAC %s, will clean up old ones",
             nFoundCount, haddrtoa(pMac, nMacLen, ':'));
    }
    
    // 2. 删除该 MAC 的所有旧记录（保留 pKeep）
    //    使用从后向前的遍历，避免删除元素影响索引
    if (nAllocatedIP > 0)
    {
        int nDeleted = 0;
        for (Ark = nAllocatedIP - 1; Ark >= 0; Ark--)
        {
            struct LL_IP *pItem = tMAC[Ark];
            
            if (!IsMacEmpty(pItem) &&
                memcmp(pItem->sMacAddr, pMac, min(nMacLen, 6)) == 0)
            {
                // 这是一个匹配的记录
                if (pItem != pKeep)
                {
                    LOG(5, "Deleting duplicate allocation: IP %s for MAC %s",
                         inet_ntoa(pItem->dwIP),
                         haddrtoa(pMac, nMacLen, ':'));
                    DHCPDestroyItem(pItem);
                    nDeleted++;
                }
            }
        }
        
        if (nDeleted > 0)
        {
            LOG(5, "Cleanup completed: deleted %d old allocation(s) for MAC %s, keep IP %s",
                 nDeleted, haddrtoa(pMac, nMacLen, ':'),
                 pKeep ? inet_ntoa(pKeep->dwIP) : "none");
        }
    }
    
    if (pKeep)
    {
        LOG(12, "Kept allocation: IP %s for MAC %s",
             inet_ntoa(pKeep->dwIP),
             haddrtoa(pMac, nMacLen, ':'));
    }
    
    // 返回删除的记录数量（nFoundCount - 1 表示删除了 nFoundCount-1 个旧记录）
    if (nFoundCount > 0)
    {
        return nDeleted;
    }
    return 0;
}


#if 0 //We are no longer using the registry
// Search in configuration file/registry by Mac Address
struct LL_IP *DHCPSearchByRegistry (const unsigned char *pMac, int nMacLen)
{
int           Rc;
HKEY          hKey;
char          szIP[20];
DWORD dwSize;

   if (nMacLen!=6) return NULL; // work only for Ethernet and Token Ring
   szIP[0] = 0;

   Rc = RegOpenKeyEx (HKEY_LOCAL_MACHINE,    // Key handle at root level.
                      TFTPD32_DHCP_KEY,      // Path name of child key.
                      0,                        // Reserved.
                      KEY_READ,                // Requesting read access.
                    & hKey) == ERROR_SUCCESS;                    // Address of key to be returned.
   
   if (Rc)  READKEY (haddrtoa(pMac, nMacLen), szIP);
   CloseHandle (hKey);

   if (isdigit (szIP[0]))    // entry has been found
        return DHCPReallocItem (NULL, inet_addr (szIP), pMac, nMacLen);
return NULL;
} // DHCPSearchByRegistry
#endif


// ---------------------------------------------------------------------
// Sample code PJO Nov 2013  
// send a broadcaast on all interfaces except the loopback
// that was used as POC to show how badly Windows 7 manage broadcasts  
// ---------------------------------------------------------------------
int DHCPSendFrom (struct sockaddr_in *pFrom, struct sockaddr_in *pTo, struct dhcp_packet *pDhcpPkt, int nSize);
#define CLASS_A_LOOPBACK  127

int DHCPMultiSend (struct sockaddr_in *pTo, struct dhcp_packet *pDhcpPkt, int nSize)
{
int Rc;
DWORD Ark;
char sFrom[64];
ADDRINFO Hints, *res;
MIB_IPFORWARDTABLE *pForwardTable;
MIB_IPFORWARDROW *pRow;
ULONG forwardTableSize=0;

   // get info for bind
   memset (& Hints, 0, sizeof Hints);
   Hints.ai_family = AF_INET;
   Hints.ai_socktype = SOCK_DGRAM;
   strncpy (sFrom, inet_ntoa (pDhcpPkt->siaddr), sizeof sFrom);
   sFrom[sizeof sFrom -1]=0;
   //Rc =     getaddrinfo (bUniCast ? NULL : sFrom, "bootps", & Hints, & res );
   Rc =     getaddrinfo (NULL , "bootps", & Hints, & res );
   if (Rc==-1)
   {
		Rc = WSAGetLastError ();
		return FALSE;
   }

   // now it is necessary to parse the routing table to check all 255.255.255.255 entries
   // and send the datagram on all of them
   Rc = GetIpForwardTable(NULL, &forwardTableSize, FALSE);
   if (Rc!=ERROR_INSUFFICIENT_BUFFER)
   {
		Rc = WSAGetLastError ();
		freeaddrinfo (res);
		return FALSE;
   }
   pForwardTable = (MIB_IPFORWARDTABLE *) malloc (forwardTableSize);
   Rc = GetIpForwardTable(pForwardTable, &forwardTableSize, FALSE);

   for (Ark=0;  Ark < pForwardTable->dwNumEntries; Ark++)
   {
          pRow = &pForwardTable->table[Ark];
          if (      pRow->dwForwardDest == htonl (INADDR_NONE) 
				&&  pRow->dwForwardMask == ULONG_MAX
				&&  pRow->dwForwardType == MIB_IPROUTE_TYPE_DIRECT
				&&  ((struct in_addr *) &pRow->dwForwardNextHop)->S_un.S_un_b.s_b1 != CLASS_A_LOOPBACK )
		  {

 			 (* (struct sockaddr_in *) res->ai_addr).sin_addr.S_un.S_addr = pRow->dwForwardNextHop;
			  DHCPSendFrom ((struct sockaddr_in *) res->ai_addr, pTo, pDhcpPkt, nSize);
		  }
   } // for all broadcast routing entries

   free (pForwardTable);
   freeaddrinfo (res);

return Rc;
} // DHCP Send

///////////////////////////////////////////////////
// Dual Boot Support: Architecture-specific boot file selection
///////////////////////////////////////////////////

/**
* GetBootFileByArch - Select appropriate boot file based on client architecture
*
* This function inspects the DHCP Option 93 (PXE Client Architecture ID)
* and returns the appropriate boot file:
* - For Legacy BIOS (arch ID 0x0000): returns szBootFile
* - For UEFI (arch ID >= 0x0006): returns szUefiBootFile if configured,
*   otherwise falls back to szBootFile
* - For other cases: returns szBootFile as default
*
* @param pDhcpOptions Pointer to DHCP options buffer
* @return Pointer to the appropriate boot file string
*/
const char *GetBootFileByArch(unsigned char *pDhcpOptions)
{
   unsigned short nArchId;
   
   if (pDhcpOptions == NULL)
       return sParamDHCP.szBootFile;
   
   // Search for DHCP Option 93 (PXE Client Architecture ID)
   // Format: 93 [length] [2 bytes arch id]
   unsigned char *p = pDhcpOptions + 4; // Skip magic cookie
   while (*p != DHO_END && p < pDhcpOptions + DHCP_OPTION_LEN - 3)
   {
       if (*p == DHO_PAD)
       {
           p++;
       }
       else if (*p == DHO_PXE_CLIENT_ARCH_ID && p[1] == 2)
       {
           nArchId = ntohs(*(unsigned short*)(p + 2));
           
           // Check architecture type
           if (nArchId == 0x0000)
           {
               // Legacy BIOS (Intel x86 PC)
               return sParamDHCP.szBootFile;
           }
           else
           {
               // UEFI types (EFI IA32, EFI BC, EFI Xscale, EFI IA64, ARM, ARM64, RISC-V, etc.)
               // Use szUefiBootFile if configured, otherwise fallback to szBootFile
               if (sParamDHCP.szUefiBootFile[0] == '\0')
               {
                   return sParamDHCP.szBootFile;
               }
               return sParamDHCP.szUefiBootFile;
           }
       }
       else
       {
           p += 2 + p[1];
       }
   }
   
   // Default: return Legacy BIOS boot file
   return sParamDHCP.szBootFile;
} // GetBootFileByArch


/**
 * 根据原始 MAC 字节查询静态绑定的 IP 地址
 *
 * 此函数是 DHCP_StaticAssignation 的辅助函数，
 * 用于在不需要完整 dhcp_packet 结构的情况下查询静态绑定
 *
 * @param pMac MAC 地址字节数组
 * @param nMacLen MAC 地址长度
 * @return 静态绑定的 IP 地址（如果存在），否则返回 INADDR_NONE
 */
DWORD DHCP_StaticAssignationByRawMac(const unsigned char *pMac, int nMacLen)
{
    char szIP[20];
    
    // 只支持以太网硬件类型（MAC 地址长度为 6）
    if (nMacLen != 6)
        return INADDR_NONE;
    
    // 从注册表或 INI 文件读取静态绑定配置
    // 使用 MAC 地址作为键值查找对应的 IP
    if (ReadKey(TFTPD32_DHCP_KEY,
                haddrtoa(pMac, nMacLen, ':'),
                szIP, sizeof(szIP),
                REG_SZ,
                szTftpd32IniFile))
    {
        LOG(5, "Static IP binding found for MAC %s: %s",
             haddrtoa(pMac, nMacLen, ':'), szIP);
        return inet_addr(szIP);
    }
    
    LOG(12, "No static IP binding found for MAC %s",
         haddrtoa(pMac, nMacLen, ':'));
    return INADDR_NONE;
} // DHCP_StaticAssignationByRawMac