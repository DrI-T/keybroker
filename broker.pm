#
# Intent:
#  create keys for file encryption and provide user keys to decrypt it.
#
# Note:
#   This work has been done during my time at Doctor I·T
#
# LICENSE:
# -- PublicDomain CC0 drit, 2021 : https://creativecommons.org/publicdomain/zero/1.0/ --
#
BEGIN { if (-e $ENV{SITE}.'/lib') { use lib $ENV{SITE}.'/lib'; } }
#
package broker;
require Exporter;
@ISA = qw(Exporter);
# Subs we export by default.
@EXPORT = qw();
# Subs we will export if asked.
#@EXPORT_OK = qw(nickname);
@EXPORT_OK = grep { $_ !~ m/^_/ && defined &$_; } keys %{__PACKAGE__ . '::'};

use strict;

# The "use vars" and "$VERSION" statements seem to be required.
use vars qw/$dbug $VERSION/;
# ----------------------------------------------------
our $VERSION = sprintf "%d.%02d", q$Revision: 0.0 $ =~ /: (\d+)\.(\d+)/;
my ($State) = q$State: Exp $ =~ /: (\w+)/; our $dbug = ($State eq 'dbug')?1:0;
# ----------------------------------------------------
$VERSION = &version(__FILE__) unless ($VERSION ne '0.00');
printf STDERR "--- # %s: %s %s\n",__PACKAGE__,$VERSION,join', ',caller(0)||caller(1);
# -----------------------------------------------------------------------
sub encode_mbase58 {
  my $mh = sprintf'Z%s',&encode_base58f(@_);
  return $mh;
}
sub decode_mbase58 {
  return &decode_base58f(substr($_[0],1));
}

sub dataKey() { # Ex. my $dkf = &dataKey($skd,$pko,$nonce,'mfs:/safewatch/etc/passwd');
  intent "generate symmetric key for data-protection";
  use encode qw(encode_mbase58);
  use XORCipher qw(xorEncrypt);
  my ($device,$recipient,$nonce,$mutaddr) = @_;
  debug "in: %s\n",YAML::XS::Dump(\@_);
  my $DH = {}; %$DH = &DHSecret($device,$recipient);
  my $dhsecret = $DH->{secret_raw};
  my $dpk = &KHMAC('SHA256',$dhsecret,$nonce,$mutaddr);
  my $khash = &khash('SHA256',$mutaddr,$dhsecret);
  debug "khash: %s\n", &encode_mbase58($khash);
  my $acckey = &xorEncrypt($dpk,$khash);
  my $dpk58 = &encode_mbase58($dpk);
  my $acckey58 = &encode_mbase58($acckey);
  debug "symkey: %s\n", $dpk58;
  debug "acckey: %s\n", $acckey58;
  return wantarray ? ($dpk58,$acckey58) : $dpk;
}

sub xencKDF($$$$) { # Ex. my $xku = &xencKDF($sko,$pku,$dpk,$mutaddr);
  intent qq'xor encrypt key derivation function for accesskey';
  use encode qw(decode_mbase58 encode_mbase58);
  use XORCipher qw(xorEncrypt);
  my ($ownKey,$pubKey,$symkey,$mutaddr) = @_;
  $symkey = &decode_mbase58($symkey) if ($symkey =~ m/^Z/);
  my $DHu = {}; %$DHu = &DHSecret($ownKey,$pubKey);
  my $khashu = &khash('SHA256',$mutaddr,$DHu->{secret_raw}); # allays keyed-hash "secret part" of xor argument
  debug "khash: %s\n", &encode_mbase58($khashu);
  my $acckey = &xorEncrypt($symkey,$khashu);
  my $acckey58 = &encode_mbase58($acckey);
  returning;
  return $acckey58;
}
sub xdecKDF($$$$) { # Ex. my $dpk = &xencKDF($sku,$pko,$xku,$mutaddr);
  intent qq'xor decrypt key derivation function for symkey';
  use encode qw(decode_mbase58 encode_mbase58);
  use XORCipher qw(xorEncrypt);
  my ($privKey,$pubKey,$acckey,$mutaddr) = @_;
  $acckey = &decode_mbase58($acckey) if ($acckey =~ m/^Z/);
  my $DH = {}; %$DH = &DHSecret($privKey,$pubKey);
  my $khash = &khash('SHA256',$mutaddr,$DH->{secret_raw}); # allays keyed-hash "secret part" of xor argument
  debug "khash: %s\n", &encode_mbase58($khash);
  my $symkey = &xorDecrypt($acckey,$khash);
  debug "acckey: %s\n", &encode_mbase58($acckey);
  debug "xdecKDF.symkey: %s\n", &encode_mbase58($symkey);
  #y $symkey58 = &encode_mbase58($symkey);
  returning;
  return $symkey;
}

sub xKDF($$$$) { # Ex. my $dkf = &xKDF($sku,$pko,$xkey,$mutaddr);
  intent qq'xor based key derivation function for cryptrees';
  use encode qw(decode_mbase58 encode_mbase58);
  use XORCipher qw(xorDecrypt);
  # same but verbose !
  my ($privKey,$ownKey,$xkey,$mutaddr) = @_;
  $xkey = &decode_mbase58($xkey) if ($xkey =~ m/^Z/);
  debug "xkey: %s\n",&encode_mbase58($xkey);
  debug "ownKey: %s\n",$ownKey;
  debug "privKey: %s\n",$privKey;
  my $DH = {}; %$DH = &DHSecret($privKey,$ownKey);
  my $dhsecret = $DH->{secret_raw};
  debug "dhsecret: %s\n",&encode_mbase58($dhsecret);
  my $khash = &khash('SHA256',$mutaddr,$dhsecret); # allays keyed-hash "secret part" of xor argument
  debug "khash: %s\n", &encode_mbase58($khash);
  my $symkey = &xorDecrypt($xkey,$khash);
  returning;
  return $symkey;
}

sub accessKey($$$$$) { # Ex. my $xku = &accessKey($sko,$pkd,$xkd,$pku,'mfs:/my/file.json');
  intent "create access key to decrypt data-protection-key";
  use misc qw(khash);
  use encode qw(decode_mbase58 encode_mbase58);
  use XORCipher qw(xorDecrypt xorEncrypt);
  my ($ownKey,$devKey,$xkd,$pubKey,$mutaddr) = @_;
  $xkd = &decode_mbase58($xkd) if ($xkd =~ m/^Z/);
  my $DHd = {}; %$DHd = &DHSecret($ownKey,$devKey);
  my $khashd = &khash('SHA256',$mutaddr,$DHd->{secret_raw}); # allays keyed-hash "secret part" of xor argument
  debug "khashd: %s\n", &encode_mbase58($khashd);
  my $DHu = {}; %$DHu = &DHSecret($ownKey,$pubKey);
  my $khashu = &khash('SHA256',$mutaddr,$DHu->{secret_raw}); # allays keyed-hash "secret part" of xor argument
  debug "khashu: %s\n", &encode_mbase58($khashu);
  my $symkey = &xorDecrypt($xkd,$khashd);
  my $acckey = &xorEncrypt($symkey,$khashu);
  my $acckey58 = &encode_mbase58($acckey);
  returning;
  return $acckey58;
}


sub XDH($$$) { # Ex. my $symkey = &xdh($reader,$opubkey,$rkeyx);
  my $intent = "compute the XOR Diffie Hellman key (/!\\ unsafe)";
  my ($reader,$owner,$rkx) = @_;
  my $DH = {}; %$DH = &DHSecret($reader,$owner);
  my $SSro = &DH->{secret_raw};
  my $xdh = &keyXor($SSro,$rkx); # /!\ might leak SSro
  return $xdh;
}

sub keyXor($$) { # Ex. my $xku = &keyXor($SS,$dkf);
  #y $intent = "simple xor of base58 encoded string...";
  use encode qw(decode_mbase58 encode_mbase58);
  my ($ssu,$dkf)  = @_;
  debug "ssu: %s\n",$ssu;
  debug "dkf: %s\n",$dkf;
  my $ssu_raw = ($ssu =~ m/^Z/) ? &decode_mbase58($ssu) : $ssu;
  my $dkf_raw = ($dkf =~ m/^Z/) ? &decode_mbase58($dkf) : $dkf;
  my $xku_raw = &xor($ssu_raw,$dkf_raw);
  my $xku = &encode_mbase58($xku_raw);
  return $xku;
}

sub KHMAC($$@) { # Ex. my $kmac = &KHMAC($algo,$secret,$nonce,$message);
  #y $intent = qq'to compute a keyed hash message authentication code';
  use Crypt::Mac::HMAC qw();
  my $algo = shift;
  my $secret = shift;
  #printf "KHMAC.secret: f%s\n",unpack'H*',$secret;
  my $digest = Crypt::Mac::HMAC->new($algo,$secret);
     $digest->add(join'',@_);
  return $digest->mac;
}

sub DHSecret { # Ex my $secret = DHSecret($sku,$pku);
  my $intent = "reveals the share secret between 2 parties !";
  my ($prikey,$pubkey) = @_;

  use encode qw(decode_mbase58 encode_mbase58);
  my $public_raw = &decode_mbase58($pubkey);
  my $private_raw = &decode_mbase58($privkey);

  my $curve = 'secp256k1';
  use Crypt::PK::ECC qw();
  my $sk  = Crypt::PK::ECC->new();
  my $priv = $sk->import_key_raw($private_raw, $curve);
  my $pk = Crypt::PK::ECC->new();
  my $pub = $pk->import_key_raw($public_raw ,$curve);
  my $shared_secret = $priv->shared_secret($pub);
  my $secret58 = &encode_mbase58($shared_secret);

  my $public = $priv->export_key_raw('public_compressed');
  my $public58 = &encode_mbase58($public);

  my $obj = {
    secret_raw => $shared_secret,
    origin => $public58,
    public => $pubkey,
    secret => $secret58
  };
  return wantarray ? %{$obj} : $obj->{secret};
}

sub xor { # Ex. my $res = xor($a,$b);
 #y $intent = "crude bitwise Xor of strings (padded to 64bit boundary)";
 my @a = unpack'Q*',$_[0] . "\0"x7;
 my @b = unpack'Q*',$_[1] . "\0"x7;
 my @x = ();
 foreach my $i (0 .. $#a) {
   $x[$i] = $a[$i] ^ $b[$i];
   printf "%08X = %08X ^ %08X\n",$x[$i],$a[$i],$b[$i] if $dbug;
 }
 my $x = pack'Q*',@x;
}


# -----------------------------------------------------------------------
sub xorEncrypt($$) {
  intent "xor encrypt a key";
  my ($d,$k,$s) = @_; # /!\ insecure if k smaller than d
  use seed qw(rand64);
  my $s ||= pack'N',rand64();
  #$s = pack'N',0;
  my @data = (0,unpack'N*',$d);
  my @key =(0,unpack'N*',$k."\0"x3);
  debug "s: %s\n",join'.',map { sprintf'%08x',$_ } unpack'N*',$s;
  debug "d: %s\n",join'.',map { sprintf'%08x',$_ } @data;
  debug "k: %s\n",join'.',map { sprintf'%08x',$_ } @key;
  my @res = map { unpack'N',$s } (0 .. $#data);
  #$res[-1] = $s;
  debug "r: %s\n",join'.',map { sprintf'%08x',$_ } @res;
  my $mod = scalar(@key);
  for my $i (0 .. $#data) {
    $res[$i] = $res[$i-1] ^ $data[$i] ^ $key[$i % $mod];
    debug "%d: %08X = %08X ^ %08X ^ %08X\n",$i,$res[$i],$res[$i-1],$data[$i],$key[$i % $mod] if $dbug;
  }
  my $x = pack 'N*',@res;
  debug "x: %s\n",join'.',map { sprintf'%08x',$_ } unpack'N*',$x;
  returning;
  return $x;

}
# -----------------------------------------------------------------------
sub xorDecrypt($$) {
  intent "xor decrypt a key";
  my ($x,$k) = @_; # /!\ insecure if k smaller than d
  my @cipher = unpack'N*',$x."\0"x3;;
  my @key = (0,unpack'N*',$k."\0"x3);
  my @res = map { 0 } (0 .. $#cipher);
  my $mod = scalar(@key);
  for my $i (0 .. $#cipher) {
    $res[$i] = $cipher[$i-1] ^ $cipher[$i] ^ $key[$i % $mod];
    debug "%d: %08X = %08X ^ %08X ^ %08X\n",$i,$res[$i],$cipher[$i-1],$cipher[$i],$key[$i % $mod] if $dbug;
  }
  shift@res;
  my $d = pack 'N*',@res;
  debug "d: %s\n",join'.',map { sprintf'%08x',$_ } unpack'N*',$d;
  returning;
  return $d;
}
# -----------------------------------------------------------------------
sub version {
  #y $intent = "get time based version string and a content based build tag";
  #y ($atime,$mtime,$ctime) = (lstat($_[0]))[8,9,10];
  my @times = sort { $a <=> $b } (lstat($_[0]))[9,10]; # ctime,mtime
  my $vtime = $times[-1]; # biggest time...
  my $version = &rev($vtime);

  if (wantarray) {
     my $shk = &get_shake(160,$_[0]);
     print "$_[0] : shk:$shk\n" if $dbug;
     my $pn = unpack('n',substr($shk,-4)); # 16-bit
     my $build = &word($pn);
     return ($version, $build);
  } else {
     return sprintf '%g',$version;
  }
}
# -----------------------------------------------------------------------
sub rev { # get revision numbers
  my ($sec,$min,$hour,$mday,$mon,$yy,$wday,$yday) = (localtime($_[0]))[0..7];
  my $rweek=($yday+&fdow($_[0]))/7;
  my $rev_id = int($rweek) * 4;
  my $low_id = int(($wday+($hour/24)+$min/(24*60))*4/7);
  my $revision = ($rev_id + $low_id) / 100;
  return (wantarray) ? ($rev_id,$low_id) : $revision;
}
# -----------------------------------------------------------------------
sub fdow { # get January first day of week
   my $tic = shift;
   use Time::Local qw(timelocal);
   ##     0    1     2    3    4     5     6     7
   #y ($sec,$min,$hour,$day,$mon,$year,$wday,$yday)
   my $year = (localtime($tic))[5]; my $yr4 = 1900 + $year ;
   my $first = timelocal(0,0,0,1,0,$yr4);
   our $fdow = (localtime($first))[6];
   #printf "1st: %s -> fdow: %s\n",&hdate($first),$fdow;
   return $fdow;
}
# -----------------------------------------------------------------------
sub get_shake { # use shake 256 because of ipfs' minimal length of 20Bytes
  use Crypt::Digest::SHAKE;
  my $len = shift;
  local *F; open F,$_[0] or do { warn qq{"$_[0]": $!}; return undef };
  #binmode F unless $_[0] =~ m/\.txt/;
  my $msg = Crypt::Digest::SHAKE->new(256);
  $msg->addfile(*F);
  my $digest = $msg->done(($len+7)/8);
  return $digest;
}
# -----------------------------------------------------------------------
sub khash { # keyed hash
   use Crypt::Digest qw();
   my $alg = shift;
   my $data = join'',@_;
   my $msg = Crypt::Digest->new($alg) or die $!;
      $msg->add($data);
   my $hash = $msg->digest();
   return $hash;
}
# -----------------------------------------------------------------------
sub word { # 20^4 * 6^3 words (25bit worth of data ...)
 use integer;
 my $n = $_[0];
 my $vo = [qw ( a e i o u y )]; # 6
 my $cs = [qw ( b c d f g h j k l m n p q r s t v w x z )]; # 20
 my $str = '';
 if (1 && $n < 26) {
 $str = chr(ord('a') +$n%26);
 } else {
 $n -= 6;
 while ($n >= 20) {
   my $c = $n % 20;
      $n /= 20;
      $str .= $cs->[$c];
   #print "cs: $n -> $c -> $str\n";
      $c = $n % 6;
      $n /= 6;
      $str .= $vo->[$c];
   #print "vo: $n -> $c -> $str\n";

 }
 if ($n > 0) {
   $str .= $cs->[$n];
 }
 return $str;
 }
}
# -----------------------------------------------------------------------
1; # $Source: /my/perl/modules/broker.pm $
