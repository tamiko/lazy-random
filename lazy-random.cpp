/* 
 * lazy-random - a fast rng-pipe. 
 *
 * Copyright (C) 2009 Matthias Maier (matthias_maier@gmx.de) 
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 */

/* 
 * lazy-random generates cryptographical strong pseudo-random numbers using
 * AES in counter-mode. 
 * We have to care about the fact that in counter-mode no block-value will
 * be repeated. So, to prevent statistical attacks,  we rekey every 16Mb.
 *
 * For the rekeying-process it is assumed that cryptographical strong
 * random numbers are available via stdin. (e.g. </dev/urandom lazy-random)
 *
 * This program uses the crypto++-library (http://cryptopp.com). Thank you
 * guys. You're awesome!
 */
 
#include <iostream>

#include <cryptopp/misc.h>
#include <cryptopp/aes.h>

#include <boost/thread.hpp>
#include <boost/program_options.hpp>

using namespace CryptoPP;
namespace bpo = boost::program_options;

boost::mutex stdin_lock; 
boost::mutex stdout_lock; 

void worker ()
{
  byte key[AES::MAX_KEYLENGTH], counter[AES::BLOCKSIZE], junk[1024];
  AES::Encryption aesEncryption(key, AES::MAX_KEYLENGTH);

  /* Initialize the counter to an arbitrary value */
  {
    boost::mutex::scoped_lock lock(stdin_lock);
    std::cin.read(reinterpret_cast<char*>(counter),AES::BLOCKSIZE);
  }
  while(true) {
    {
      boost::mutex::scoped_lock lock(stdin_lock);
      std::cin.read(reinterpret_cast<char*>(key),AES::MAX_KEYLENGTH);
    }
    aesEncryption.SetKey(key, AES::MAX_KEYLENGTH);

    for( int i = 0; i < 16*1024;i++) {
      /* 1kb-Junks seem to be ideal. */
      for (int j = 0; j < 1024/AES::BLOCKSIZE;j++) {
        IncrementCounterByOne(counter,AES::BLOCKSIZE);
        aesEncryption.ProcessBlock(counter,&junk[j*AES::BLOCKSIZE]);
      }
      {
        boost::mutex::scoped_lock lock(stdout_lock);
        std::cout.write(reinterpret_cast<char*>(junk),1024);  
      }
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
       "By default one thread will be spawned.");

  try {
    bpo::variables_map vm;
    bpo::store (bpo::parse_command_line(argc, argv, desc), vm);
    bpo::notify(vm);
  } catch (...) {
    std::cerr << "\nlazy-random Version: 0.2"
              << "\nCopyright (C) 2009 Matthias Maier "
                  "<tamiko@kyomu.43-1.org>\n\n"
              << desc;
    return 1;
  }

  if (no_of_threads < 0 || no_of_threads > 255) {
    std::cerr <<"Invalid number of threads: " <<no_of_threads <<std::endl;
    return 1;
  }

  boost::thread_group my_group;
  for (int i = 1; i <= no_of_threads; i++)
    my_group.create_thread(worker);
  my_group.join_all();
}
