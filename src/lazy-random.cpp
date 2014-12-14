/*
 * lazy-random - a fast rng-pipe.
 *
 * Copyright (C) 2009 - 2014 Matthias Maier <tamiko@kyomu.43-1.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Matthias Maier "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL Matthias Maier OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * lazy-random generates cryptographical strong pseudo-random numbers using
 * AES in counter-mode.
 * We have to care about the fact that in counter-mode no block-value will
 * be repeated. So, to prevent statistical attacks, we rekey every 16Mb.
 *
 * For the rekeying-process it is assumed that cryptographical strong
 * random numbers are available via stdin, e.g.
 *
 *   $ </dev/urandom lazy-random
 *
 * This program uses the crypto++-library (http://cryptopp.com). Thank you
 * guys. You're awesome!
 */

#include <iostream>

#include "misc.h"
#include "aes.h"

#include "boost/thread.hpp"
#include "boost/program_options.hpp"

/* REKEYSIZE has to be a multiple of JUNKSIZE */
#define REKEYSIZE (16*1024*1024)
/* JUNKSIZE has to be a multiple of AES::BLOCKSIZE */
#define JUNKSIZE (1024*1024)

/* Some workaround ... */
#define CRYPTOPP_DISABLE_ASM

using namespace CryptoPP;
namespace bpo = boost::program_options;

void worker ()
{
  byte key[AES::MAX_KEYLENGTH], counter[AES::BLOCKSIZE], junk[JUNKSIZE];
  AES::Encryption aesEncryption(key, AES::MAX_KEYLENGTH);

  /* Initialize the counter to an arbitrary value */
  std::cin.read(reinterpret_cast<char*>(counter),AES::BLOCKSIZE);
  std::cout.exceptions(std::ostream::failbit | std::ostream::badbit);

  for(;;) {

    std::cin.read(reinterpret_cast<char*>(key),AES::MAX_KEYLENGTH);
    aesEncryption.SetKey(key, AES::MAX_KEYLENGTH);

    for( int i = 0; i < REKEYSIZE/JUNKSIZE;i++) {
      for (int j = 0; j < JUNKSIZE/AES::BLOCKSIZE;j++) {
        IncrementCounterByOne(counter,AES::BLOCKSIZE);
        aesEncryption.ProcessBlock(counter,&junk[j*AES::BLOCKSIZE]);
      }

      std::cout.write(reinterpret_cast<char*>(junk),JUNKSIZE);
    }
  }
}


int main(int argc, char** argv)
{
  int no_of_threads;

  bpo::options_description desc("Allowed options");
  desc.add_options()
    ( "threads",
      bpo::value<int>(&no_of_threads)->default_value(1),
      "Number of threads. Allowed range is 0-255.\n"
       "By default one thread will be spawned.")
    ;

  try {
    bpo::variables_map vm;
    bpo::store (bpo::parse_command_line(argc, argv, desc), vm);
    bpo::notify(vm);
  } catch (...) {
    std::cerr << "\nlazy-random Version: 0.4"
              << "\nCopyright (C) 2009 - 2014 Matthias Maier "
                  "<tamiko@kyomu.43-1.org>\n\n"
              << desc;
    return 1;
  }

  if (no_of_threads < 0 || no_of_threads > 255) {
    std::cerr << "Invalid number of threads: " << no_of_threads
              << std::endl;
    return 1;
  }

  boost::thread_group my_group;
  for (int i = 1; i <= no_of_threads; i++)
    my_group.create_thread(worker);
  my_group.join_all();
}
