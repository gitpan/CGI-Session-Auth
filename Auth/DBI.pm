###########################################################
# CGI::Session::Auth::DBI
# Authenticated sessions for CGI scripts
# Copyright (c) 2003 Jochen Lillich <jl@teamlinux.de>
###########################################################
#
# $Id: DBI.pm,v 1.6 2003/10/31 08:28:33 jlillich Exp $
#

package CGI::Session::Auth::DBI;
use base qw(CGI::Session::Auth);

use 5.008;
use strict;
use warnings;
use Carp;
use DBI;

our $VERSION = do { my @r = (q$Revision: 1.6 $ =~ /\d+/g); sprintf "%d." . "%03d" x (scalar @r - 1), @r; };

# column names in database
my $COL_USERID = 'userid';
my $COL_USERNAME = 'username';
my $COL_PASSWORD = 'passwd';
my $COL_IPUSERID = 'userid';
my $COL_IPADDR = 'network';
my $COL_IPMASK = "netmask";

###########################################################
###
### general methods
###
###########################################################

###########################################################

sub new {
    
    ##
    ## build new class object
    ##
    
    my $class = shift;
    my ($params) = shift;
    
    $class = ref($class) if ref($class);
    
    # initialize parent class
    my $self = $class->SUPER::new($params);
    
    #
    # class specific parameters
    #
    
    # parameter 'DSN': DBI data source name
    my $dsn = $params->{DSN} || croak("No DSN parameter");
    # parameter 'DBUser': database connection username
    my $dbuser = $params->{DBUser} || '';
    # parameter 'DBPasswd': database connection password
    my $dbpasswd = $params->{DBPasswd} || "";
    # parameter 'DBAttr': optional database connection attributes
    my $dbattr = $params->{DBAttr} || {};
    # parameter 'UserTable': name of user data table
    $self->{usertable} = $params->{UserTable} || 'auth_user';
    # parameter 'GroupTable': name of user data table
    $self->{grouptable} = $params->{GroupTable} || 'auth_group';
    # parameter 'IPTable': name of ip network table
    $self->{iptable} = $params->{IPTable} || 'auth_ip';
    
    #
    # class members
    #
    
    # database handle
    $self->{dbh} = DBI->connect($dsn, $dbuser, $dbpasswd, $dbattr) or croak("DB error: " . $DBI::errstr);
    
    # blessed are the greek
    bless($self, $class);
    
    return $self;
}

###########################################################
###
### backend specific methods
###
###########################################################

###########################################################

sub _login {
    
    ##
    ## check username and password
    ##
    
    my $self = shift;
    my ($username, $password) = @_;
    
    $self->_debug("username: $username, password: $password");
    
    my $result = 0;
    
    my $query = sprintf(
        "SELECT * FROM %s WHERE %s = ? AND %s = ?",
        $self->{usertable},
        $COL_USERNAME,
        $COL_PASSWORD
    );
    $self->_debug("query: $query");
    # search for username
    my $sth = $self->_dbh->prepare($query);
    $sth->execute($username, $password) or croak $self->_dbh->errstr;
    if (my $rec = $sth->fetchrow_hashref) {
        $self->_debug("found user entry");
        $self->_extractProfile($rec);
        $result = 1;
        $self->_info("user '$username' logged in");
    }
    $sth->finish;
    
    return $result;
}

###########################################################

sub _ipAuth {
    
    ##
    ## authenticate by the visitors IP address
    ##
    
    my $self = shift;
    
    require NetAddr::IP;
    
    my $remoteip = new NetAddr::IP($self->_cgi->remote_host);
    $self->_debug("checking remote IP $remoteip");
    
    my $result = 0;
    
    my $query = sprintf(
        "SELECT %s, %s, %s FROM %s",
        $COL_IPUSERID,
        $COL_IPADDR,
        $COL_IPMASK,
        $self->{iptable}
    );
    $self->_debug("query: $query");
    
    # search for username
    my $sth = $self->_dbh->prepare($query);
    $sth->execute or croak $self->_dbh()->errstr;
    while (my $rec = $sth->fetchrow_hashref) {
        
        $self->_debug("compare IP network ", $rec->{$COL_IPADDR}, "/", $rec->{$COL_IPMASK});
        
        if ($remoteip->within(new NetAddr::IP( $rec->{$COL_IPADDR}, $rec->{$COL_IPMASK}))) {
            $self->_debug("we have a winner!");
            # get user record
            my $user = $self->_getUserRecord($rec->{$COL_IPUSERID});
            $self->_extractProfile($user);
            $result = 1;
            last;
        }
        else {
            $self->_debug("no member of this network");
        }
        
    }
    $sth->finish;
    
    return $result;
}

###########################################################

sub _loadProfile {
    
    ##
    ## get user profile from database by userid
    ##
    
    my $self = shift;
    my ($userid) = @_;
    
    my $query = sprintf(
        "SELECT * FROM %s WHERE userid = ?",
        $self->{usertable}
    );
    $self->_debug("query: $query");
    my $sth = $self->_dbh->prepare($query);
    $sth->execute($userid) or croak $self->_dbh()->errstr;
    if (my $rec = $sth->fetchrow_hashref) {
        $self->_debug("Found user entry");
        $self->_extractProfile($rec);
    }
    $sth->finish;
}

###########################################################

sub saveProfile {

    ##
    ## save probably modified user profile
    ##

    my $self = shift;
    
    my $query = "UPDATE " . $self->{usertable} . " SET ";
    my @values;
    my $first = 1;
	foreach (keys %{$self->{profile}}) {
		if ($_ ne $COL_USERID) {
			$query .= (($first) ? '' : ', ') . $_ . " = ?";
			push @values, $self->{profile}{$_};
			$first = 0;
		}
	}
	$query .= " WHERE " . $COL_USERID . " = ?";
	$self->_debug("update query: ", $query);

    my $sth = $self->_dbh()->prepare($query);
    $sth->execute(@values, $self->{userid}) or croak $self->_dbh()->errstr;
	    
}

###########################################################

sub isGroupMember {
    
    ##
    ## check if user is in given group
    ##
    
}

###########################################################
###
### internal methods
###
###########################################################

###########################################################

sub _dbh {
    
    ##
    ## return database handle
    ##
    
    my $self = shift;
    
    return $self->{dbh};
}

###########################################################

sub _extractProfile {
    
    ##
    ## get user profile from database record
    ##
    
    my $self = shift;
    my ($rec) = @_;
    
    $self->{userid} = $rec->{$COL_USERID};
    foreach ( keys %$rec ) {
        $self->{profile}{$_} = $rec->{$_};
    }
};

###########################################################

sub _getUserRecord {
    
    ##
    ## get user data by user id
    ##
    
    my $self = shift;
    my ($userid) = @_;
    
    $self->_debug("get data for userid: ", $userid);
    
    my $query = sprintf(
        "SELECT * FROM %s WHERE %s = ?",
        $self->{usertable},
        $COL_USERID
    );
    $self->_debug("query: $query");
    # search for username
    my $sth = $self->_dbh->prepare($query);
    $sth->execute($userid) or croak _dbh->errstr;
    
    return $sth->fetchrow_hashref;
}

###########################################################
###
### end of code, module documentation below
###
###########################################################

1;
__END__

=head1 NAME

CGI::Session::Auth::DBI - Authenticated sessions for CGI scripts

=head1 SYNOPSIS

  use CGI;
  use CGI::Session;
  use CGI::Session::Auth::DBI;

  my $cgi = new CGI;
  my $session = new CGI::Session(undef, $cgi, {Directory=>'/tmp'});
  my $auth = new CGI::Session::Auth({
      CGI => $cgi,
      Session => $session,
      DSN => 'dbi:mysql:host=localhost,database=cgiauth',
  });
  $auth->authenticate();
  
  if ($auth->loggedIn) {
      showSecretPage;
  }
  else {
      showLoginPage;
  }



=head1 DESCRIPTION

CGI::Session::Auth::DBI is a subclass of L<DBI::Session::Auth>. It uses a
relational database for storing the authentication data, using the L<DBI> module
as database interface.

=head2 Database setup

Use your favourite database administration tool to create
and populate the database:

CREATE TABLE auth_user (
    userid char(32) NOT NULL,
    username varchar(30) NOT NULL,
    passwd varchar(30) NOT NULL default '',
    PRIMARY KEY (userid),
    UNIQUE username (username)
);

INSERT INTO auth_user VALUES ( '325684ec1b028eaf562dd484c5607a65', 'admin', 'qwe123' );
INSERT INTO auth_user VALUES ( 'ef19a80d627b5c48728d388c11900f3f', 'guest', 'guest' );

CREATE TABLE auth_ip (
    network char(15) NOT NULL,
    netmask char(15) NOT NULL,
    userid char(32) NOT NULL,
    PRIMARY KEY (network, netmask)
);

INSERT INTO auth_ip VALUES ('127.0.0.1', '255.0.0.0',  'ef19a80d627b5c48728d388c11900f3f' );

Mandatory columns in C<auth_user> are C<userid>, C<username> and C<passwd>.
All additional columns will also be stored and accessible as user profile fields.

C<userid> is a 32-character string and can be generated randomly by

perl -MCGI::Session::Auth -e 'print CGI::Session::Auth::_uniqueUserID("myname"), "\n";'

The C<auth_ip> table is used for IP address based authentication. Every row combines a pair of network
address and subnet mask (both in dotted quad notation) with a user ID. The C<userid> column
is used as a foreign key into the C<auth_user> table.

=head2 Constructor parameters

Additional to the standard parameters used by the C<new> constructor of
all CGI::Session::Auth classes, CGI::Session::Auth::DBI understands the following parameters:

=over 1

=item B<DSN>: Data source name for the database connection (mandatory).
For an explanation, see the L<DBI> documentation.

=item B<DBUser>: Name of the user account used for the database connection. (Default: none)

=item B<DBPasswd>: Password of the user account used for the database connection. (Default: none)

=item B<DBAttr>: Optional attributes used for the database connection. (Default: none)

=item B<UserTable>: Name of the table containing the user authentication data and profile. (Default: 'auth_user')

=item B<IPTable>: Name of the table containing the by-IP authentication data. (Default: 'auth_ip')

=back



=head1 SEE ALSO

L<CGI::Session::Auth>



=head1 AUTHOR

Jochen Lillich, E<lt>jl@teamlinux.deE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2003 by Jochen Lillich

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
