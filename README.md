## TimeLock ##

TimeLock is a simple ruby script which encrypts files using hash values computed over long time intervals.
This necessitates the use of equal processing power to decrypt these files, in essence timelocking them...

A quick explaination of this concept can be found [here](kdt.io/post/21).
For a longer explaination [this](http://www.gwern.net/Self-decrypting%20files) is a quite interesting read.

## Usage ##

You will of course need the dependencies, thus start by running `bunder install`

To lock a file:
    
    ruby timelock.rb lock -i 20 file_to_lock.txt
  
Where '-i' is the number of iterations you would like to compute.
This will generate both an encrypted file, and a time key to decrypt it later.

To unlock a file:

    ruby timelock.rb unlock file_to_unlock.timelocked

Additionally you can test the hashing speed of your device like this:

    ruby timelock.rb speedtest

         
