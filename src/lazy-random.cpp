/*
 * lazy-random - a fast random number generator.
 *
 * Copyright (C) 2009 - 2022 Matthias Maier <tamiko@kyomu.43-1.org>.
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
 * the ChaCha20 stream cipher. In order to provide some mild forward
 * secrecy we use the "fast key erasure" [1] technique every 64KiB and
 * rekey completely from /dev/urandom every 1GiB.
 *
 * [1] https://blog.cr.yp.to/20170723-random.html
 *
 * This program uses the crypto++-library (https://cryptopp.com). Thank you
 * guys. You're awesome!
 */

#include <fstream>
#include <iostream>

#include "chacha.h"
#include "osrng.h"
#include "secblock.h"

#include "boost/program_options.hpp"
#include "boost/thread.hpp"

#define CHUNKSIZE (64 * 1024)          // fast key erasure every 64KiB
#define REKEYSIZE (1024 * 1024 * 1024) // complete rekey every 1GiB
static_assert(REKEYSIZE % CHUNKSIZE == 0,
              "REKEYSIZE has to be a multiple of CHUNKSIZE");

using namespace CryptoPP;
namespace bpo = boost::program_options;


void worker()
{
  SecByteBlock key(32), iv(8);
  ChaCha::Encryption enc;

  SecByteBlock chunk(CHUNKSIZE), zeroes(CHUNKSIZE);
  zeroes.Assign(CHUNKSIZE, 0);

  std::cout.exceptions(std::ostream::failbit | std::ostream::badbit);

  for (;;) {
    // reseed from /dev/urandom:
    OS_GenerateRandomBlock(false, key, key.size());
    OS_GenerateRandomBlock(false, iv, iv.size());

    for (std::size_t i = 0; i < REKEYSIZE / CHUNKSIZE; ++i) {
      enc.SetKeyWithIV(key, key.size(), iv, iv.size());
      enc.ProcessData(key, zeroes, key.size()); /* fast key erasure */
      enc.ProcessData(chunk, zeroes, chunk.size());
      std::cout.write(reinterpret_cast<char *>(chunk.data()), CHUNKSIZE);
    }
  }
}


int main(int argc, char **argv)
{
  int no_of_threads;

  bpo::options_description desc("Allowed options");
  desc.add_options()("threads",
                     bpo::value<int>(&no_of_threads)->default_value(1),
                     "Number of threads. Allowed range is 0-255.\n"
                     "By default one thread will be spawned.");

  try {
    bpo::variables_map vm;
    bpo::store(bpo::parse_command_line(argc, argv, desc), vm);
    bpo::notify(vm);
  } catch (...) {
    std::cerr << "\nlazy-random Version: 0.5"
              << "\nCopyright (C) 2009 - 2015 Matthias Maier "
                 "<tamiko@kyomu.43-1.org>\n\n"
              << desc;
    return 1;
  }

  if (no_of_threads < 0 || no_of_threads > 255) {
    std::cerr << "Invalid number of threads: " << no_of_threads << std::endl;
    return 1;
  }

  boost::thread_group my_group;
  for (int i = 1; i <= no_of_threads; i++)
    my_group.create_thread(worker);
  my_group.join_all();
}
