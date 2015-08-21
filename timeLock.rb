require 'crypt/blowfish'
require 'scrypt'
require 'securerandom'

### Methods ###

def get_args
  args = ARGV
  mode = args.shift
  target = args.pop
  keys = {}
  while not args.empty?
    keys[args.shift] = args.shift
  end
  {:mode => mode, :target => target, :keys => keys}
end

def gen_timelock_key(iter_num, start_key=nil, salt=nil)
  original = start_key || SecureRandom.base64
  salt = salt || SCrypt::Engine.generate_salt
  iter_key = original
  iter_num.times { iter_key = SCrypt::Engine.hash_secret iter_key, salt }
  {:key => iter_key, :start => original, :iter => iter_num, :salt => salt}
end

def check_scrypt_speed(iter=50)
  start_time = Time.now
  gen_timelock_key iter
  (Time.now - start_time).to_i / iter.to_f
end


def parse_key_file(key_path)
  key = File.read(key_path).split("\n").map { |l| l.split ':' }.to_h
  key['iter'] = key['iter'].to_i
  key['temp_iter'] = ey['temp_iter'].to_i if key.has_key? 'temp_iter'
  return key
end

def timelock_file(file_path, timelock_key)
  blowfish = Crypt::Blowfish.new(timelock_key[:key][0..55])
  blowfish.encrypt_file(file_path, file_path + '.timelocked')
  File.open(file_path + '.timelockkey', 'w+') do |f|
    timelock_key.delete :key
    f << timelock_key.collect { |k, v| k.to_s + ':' + v.to_s }.join("\n")
  end
end


def un_timelock_file(file_path, timelock_key)
  blowfish = Crypt::Blowfish.new(timelock_key[:key][0..55])
  blowfish.decrypt_file(file_path, file_path.gsub(/\.timelocked$/, ''))
end

### Main ###

# Arg parsing
parsed_args = get_args
mode = parsed_args[:mode]
file = parsed_args[:target]
options = parsed_args[:keys]

# Check args

if mode == 'lock'
 if options['-i'].nil? then puts 'ERROR: no iteration number specified...'; exit end
end

if mode == 'unlock'
  if not File.exist?(file + '.timelocked')
    puts "ERROR: can't find locked file: #{(file + '.timelocked')}"
    exit
  end
  if not File.exist?(file + '.timelockkey')
    puts "ERROR: can't find key file: #{(file + '.timelockkey')}"
    exit
  end
end

if ['lock', 'unlock'].include?(mode)
  if file.nil? then puts 'ERROR: no target file.'; exit end
end


# Mode Handling
case mode
  when 'lock'
    iterations = options['-i'].to_i
    puts 'Generating timelock key... (this may take a while)'
    key = gen_timelock_key(iterations)
    puts 'Locking file...'
    timelock_file(file, key)

  when 'unlock'
    keyfile = parse_key_file (file + '.timelockkey')
    puts 'Generating timelock key from keyfile... (this may take a while)'
    key = gen_timelock_key(
      (keyfile['temp_iter'] || keyfile['iter']),
      (keyfile['temp_start'] || keyfile['start']),
      keyfile['salt']
    )
    puts 'Unlocking file...'
    un_timelock_file(file + '.timelocked', key)


  when 'speedtest'
    puts 'Running hashing speed test...'
    speed = check_scrypt_speed
    puts "Average scrypt hash took: #{speed} seconds
    min: #{(60/speed).to_i}
    hour: #{(3600/speed).to_i}
    day: #{(86400/speed).to_i}
    week: #{(604800/speed).to_i}"

  else puts 'ERROR: unknown operating mode.'
end
