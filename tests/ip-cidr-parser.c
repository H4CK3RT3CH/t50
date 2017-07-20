#include <stdio.h>
#include <assert.h>

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// Validate a single string representing an octect.
// Is valid, returns true and updates *octect, otherwise,
// returns false and *octect is undefined.
static _Bool validate_octect(char *s, uint8_t *octect)
{
  char *q;
  int n;
  _Bool r;

  // return false if empty.
  if (!*s)
    return false;

  // all chars must be numeric!
  for (q = s; *q; q++)
    if (!isdigit(*q))
      return false;

  n = atoi(s);
  r = (n >= 0 && n <= 255);
  if (r)
    *octect = n;

  return r;
}

// Returns the beginning of the string and sets *cidr.
// if no cidr exists, *cidr will be NULL.
static char *separate_ip_and_cidr(char *s, char **cidr)
{
  char *p;

  if (p = strchr(s, '/'))
    *p++ = '\0';
  *cidr = p;

  return s;
}

static _Bool validate_cidr(char *s, int *icidr)
{
  int n;

  // s can be NULL as of the return of separate_ip_and_cidr().
  // No CIDR, assume 32.
  if (!s)
  {
    *icidr = 32;
    return true;
  }

  // Checks if IPv4 CIDR is in range.
  *icidr = atoi(s);
  if (*icidr > 0 && *icidr <= 32)
    return true;

  // icidr is 0 in case of error.
  *icidr = 0;
  return false;
}

static _Bool validate_partial_ip(char *s, uint32_t *ip)
{
  char *p, *q;
  char *substrs[4];   // NOTE: Stack allocation is easier!
  uint32_t numdots, i, valid_octects;
  uint8_t o;
  _Bool r = true;

  // zero IP is an indication of error.
  *ip = 0;

  // Don't disturb the original string, we'll need it later!
  p = q = strdup(s);

  // Count the dots on IP address...
  numdots = 0;
  while (*q)
    if (*q++ == '.')
      numdots++;

  // We must have less than 4 dots: 'xxx.xxx.xxx.xxx'!
  if (numdots > 3)
  {
    r = false;
    goto validate_ip_exit;
  }

  // Substitute dots for '\0' and make copies
  // of the pointers (equivalent to spliting the string).
  q = p;
  i = 0;
  while (q)
  {
    assert(i < 4);

    substrs[i++] = q;
    q = strchr(q, '.');
    if (q) 
      *q++ = '\0';
  }  

  // If the first octect has some initial spaces, 
  // get rid of them.
  q = substrs[0];
  while (*q && isspace(*q)) q++;
  substrs[0] = q;

  // NOTE: We don't need to verify if last octect has spaces.
  // IPs can be "resolved" later by getaddrinfo(), if this
  // feature is enabled.

  // Validate the octects filling *ip.
  // It is garanteed 'numdots' is less than 4 here.
  // We need to count the valid octects to fill incomplete IPs.
  valid_octects = 0;
  for (i = 0; i <= numdots; i++)
  {
    // 'o' will be adjusted correctly if the
    // octect is valid. Otherwise we have an error.
    if (!validate_octect(substrs[i], &o))
    {
      r = false;
      goto validate_ip_exit;
    }

    valid_octects++;
    *ip = (*ip << 8) | o; // Clever, huh?
  }

  // Fill the remaining octects with zeros, shifting left.
  if (valid_octects < 4)
    *ip <<= (8 * (4 - valid_octects));

validate_ip_exit:
  free(p);    // free the duplicated string.
  return r;
}

// This is the same routine used in src/netio.c
static uint32_t resolv(char *s)
{
  uint32_t addr = 0;
  int err;
  struct addrinfo hints = { .ai_family = AF_INET },
  *res, *res0 = NULL;

  if (getaddrinfo(s, NULL, &hints, &res0))
    goto resolv_exit;

  // Retirado o suporte a IPv6.
  for (res = res0; res; res = res->ai_next)
    if (res->ai_family == AF_INET)
    {
      addr = ntohl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr);
      break;
    }

resolv_exit:
  if (res0)
    freeaddrinfo(res0);

  return addr;
}

// Finally, our actual parser:
//
// If it returns false, *ip and/or *cidr will be ser to zero.
// When *ip is zero it means an error to validate the IP or name.
// When *cidr is zero it means CIDR is out of range (1~32).
//
// If it returns true, is garanteed *ip and *cidr are correctly filled.
//
// *ip is little endian.
//
_Bool get_ip_and_cidr(char *s, _Bool use_resolver, uint32_t *ip, int *cidr)
{
  _Bool r;
  char *saddr, *scidr, *p;

  // Makes a copy here 'cause the pointer cannot point to a constant.
  p = strdup(s);

  saddr = separate_ip_and_cidr(p, &scidr);

  r = true;
  if (!validate_partial_ip(saddr, ip))
  {
    if (!use_resolver)
      r = false;
    else
    {
#ifdef DEBUG
      fputs("\x1b[33;1m[RESOLV]\x1b[0m ", stdout);
#endif
      if (!(*ip = resolv(saddr)))
        r = false;
    }
  }

  if (!validate_cidr(scidr, cidr))
    r = false;

  free(p);    // free the duplicated string.
  return r;
}

// Test routine.
void main(void)
{
  char *tests[] = { 
    "10.10.10.10/0",  // erro
    "10.10.10.10/1",  // ok
    "10.10.10.10/16", // ok
    "10.10.10.10/32", // ok
    "10.10.10.10/33", // error

    "10.10.10/24",    // ok
    "10.10.10",       // ok, ip = 0x0a0a0a00, cidr=32
    "10.10",          // ok, ip = 0x0a0a0000, cidr=32

    ".10.10.10",      // error

    "10..10.10/20",   // error
    "10...10/20",     // error

    " 10.10.10/24",   // ok

    "10.10.10 /24",   // ok

    "10.10.10./24",   // error
    "10.10.10.10./24",// error? (this should be an error, but the routine tries to resolve it)

    "10.10.10.10.10/24",// error (the routine will try to resolve it!)
    "kernel.org/24",  // ok.
    "::FFFF:10.32.12.12/32",         // ok? (error if not name resolve feature enabled).
    "2605:bc80:3010:b00:0:deb:166:202",   // debian.com ipv6 (error! not mapped to IPv4!).
    "",               // error.
    "x",              // error.
    "-1",             // error.

    NULL
  };
  char **arg;

  int cidr, i = 1;
  uint32_t addr;

  for (arg = tests; *arg; arg++)
  {
    printf("#%-2d: \"%s\" -> ", i++, *arg);
    if (!get_ip_and_cidr(*arg, true, &addr, &cidr))
      fputs("\x1b[31;1m[ERRO]\x1b[0m ", stdout);
    printf("IP (hex, little-endian) = 0x%08x, CIDR = %d\n", addr, cidr);
  }
} 
