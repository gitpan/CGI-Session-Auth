###########################################################
# CGI::Session::Auth
# Authenticated sessions for CGI scripts
# Copyright (c) 2003 Jochen Lillich <jl@teamlinux.de>
###########################################################
# 
# $Id: Auth.pm,v 1.3 2003/09/17 09:08:04 jlillich Exp $
#

package CGI::Session::Auth;
use base qw(Exporter);

use 5.008;
use strict;
use warnings;
use Carp;
use Digest::MD5 qw( md5_hex );

our %EXPORT_TAGS = ( 'all' => [ qw(
) ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw(
);

our $VERSION = '0.11';

# logging
my $LOGLEVEL = 'DEBUG';
use Log::Log4perl qw( get_logger );
my $conf = {
	'log4perl.category.CGI.Session.Auth' => "$LOGLEVEL, Logfile",
	'log4perl.appender.Logfile' => 'Log::Dispatch::File',
	'log4perl.appender.Logfile.filename' => '/tmp/cgi-session-auth.log',
	'log4perl.appender.Logfile.layout' => 'Log::Log4perl::Layout::PatternLayout',
	'log4perl.appender.Logfile.layout.ConversionPattern' => '[%d] %F{1} %M (%L): %m %n',
};
Log::Log4perl::init($conf);
my $logger = get_logger("CGI::Session::Auth");
    
###########################################################
###
### public methods
###
###########################################################
         
###########################################################

sub new {

###########################################################
#
# class constructor
#
# see POD below
#

    my $class = shift;
    my ($params) = @_;
    
    $class = ref($class) if ref($class);
    # check required params
    my %classParams = (
        Session => 'CGI::Session',
        CGI => 'CGI'
    );
    foreach (keys %classParams) {
        croak "Missing $_ option" unless exists $params->{$_};
        croak "$_ option is no $classParams{$_} object" unless $params->{$_}->isa($classParams{$_});
    }
    
    my $self = {
    	# parameter "Session": CGI::Session object
        session => $params->{Session},
        # parameter "CGI": CGI object
        cgi => $params->{CGI},
        # parameter "LoginVarPrefix": prefix of login form variables (default: 'log_')
        lvprefix => $params->{LoginVarPrefix} || 'log_',
        # parameter "DoIPAuth": enable IP address based authentication (default: 0)
        ipauth => $params->{DoIPAuth} || 0,
        
        # the current URL
        url => $params->{CGI}->url,
        # logged-in status
        logged_in => 0,
        # user id
        userid => '',
        # user profile data
        profile => {},
    };
    bless $self, $class;

    return $self;
}

###########################################################

sub init {

###########################################################
    my $self = shift;
    
    # is this already a session by an authorized user?
    if ( $self->_session->param("~logged-in") ) {
    	$logger->debug("User is already logged in in this session");
    	# set flag
    	$self->_loggedIn(1);
    	# load user profile
		my $userid = $self->_session->param('~userid');
		$self->_loadProfile($userid);
        return 1;
    }
	else {
		$logger->debug("User is not logged in in this session");
		# reset flag
		$self->_loggedIn(0);
    }
    
    # maybe someone's trying to log in?
    my $lg_name = $self->_cgi->param( $self->{lvprefix} . "username" );
    my $lg_pass = $self->_cgi->param( $self->{lvprefix} . "password" );
    
    if ($lg_name && $lg_pass) {
	    # Yes! Login data coming in.
	    $logger->debug("User trying to log in");
        if ($self->_login( $lg_name, $lg_pass )) {
        	$logger->debug("login successful, userid: ", $self->{userid});
	    	$self->_loggedIn(1);
            $self->_session->param("~userid", $self->{userid});
            $self->_session->clear(["~login-trials"]);
            return 1;
        }
        else {
            # the login seems to have failed :-(
            $logger->debug("Login failed");
            my $trials = $self->_session->param("~login-trials") || 0;
            return $self->_session->param("~login-trials", ++$trials);
        }
    }
        
    # or maybe we can authenticate the visitor by his IP address?
    if ($self->{ipauth}) {
    	# we may check the IP
    	if ($self->_ipAuth) {
        	$logger->debug("IP authentication successful, userid: ", $self->{userid});
	    	$self->_loggedIn(1);
            $self->_session->param("~userid", $self->{userid});
            $self->_session->clear(["~login-trials"]);
			return 1;
    	}
    }
    
}

###########################################################

sub loggedIn {

###########################################################
#
# get internal logged-in flag
#

	my $self = shift;

	return $self->_loggedIn;	
}

###########################################################

sub profile {

###########################################################
#
# accessor to user profile fields
#

	my $self = shift;
	my $key = shift;
	
	if (@_) {
		my $value = shift;
		$self->{profile}{$key} = $value;
	}
	
	return $self->{profile}{$key};
}
	
###########################################################

sub checkUsername {

###########################################################
#
# check for given user name
#

	my $self = shift;
	my ($username) = @_;
	
	return ($self->{profile}{username} eq $username);
}

###########################################################

sub checkGroup {

###########################################################
#
# check if user is in given group
#

	# abstract class w/o group functions, for real applications use a subclass
	return 0;
}

###########################################################

sub logout {

###########################################################
#
# revoke users logged-in status
#

	my $self = shift;
	
	$self->_loggedIn(0);
	$logger->info("User '", $self->{profile}{username}, "' logged out");
}



###########################################################
###
### private methods
###
###########################################################

###########################################################

sub sessionCookie {

###########################################################
#
# make cookie with session id
#

	my $self = shift;
	
	my $cookie = $self->_cgi->cookie(CGISESSID => $self->_session->id );
	return $cookie;
}

###########################################################

sub _session {

###########################################################
#
# get reference on CGI::Session object
#

	my $self = shift;
	
	return $self->{session};
}

###########################################################

sub _cgi {

###########################################################
#
# get reference on CGI object
#

	my $self = shift;
	
	return $self->{cgi};
}

###########################################################

sub _uniqueUserID {

###########################################################
#
# generate a unique 32-character user ID
#

	my $self = shift;
	my ($username) = @_;
	
	return md5_hex(localtime, $username);
}

###########################################################

sub _loggedIn {

###########################################################
#
# accessor to internal logged-in flag and session parameter
#

	my $self = shift;

	if (@_) {
		# set internal flag
		if ($self->{logged_in} = shift) {
			# set session parameter
            $self->_session->param("~logged-in", 1);
		}
		else {
			# clear session parameter
			$self->_session->clear(["~logged-in"]);
		}
		$logger->debug("(re)set logged_in: ", $self->{logged_in});
	}	

	# return internal flag	
	return $self->{logged_in};
}

###########################################################

sub _url {

###########################################################
	my $self = shift;
	
	return $self->{url};
}

###########################################################
###
### backend methods
###
### these methods have to be rewritten for subclasses
###
###########################################################

###########################################################

sub _login {

###########################################################
#
# check login credentials and load user profile
#

	my $self = shift;
	my ($username, $password) = @_;

	# allow only the guest user, for real applications use a subclass
	if ( ($username eq 'guest') && ( $password eq 'guest' ) ) {
		$logger->info("User '$username' logged in");
		$self->{userid} = "guest";
		$self->_loadProfile($self->{userid});
		return 1;
	}
			
	return 0;
}


###########################################################

sub _ipAuth {

###########################################################
#
# authenticate by the visitors IP address
#

	return 0;
}

###########################################################

sub _loadProfile {

###########################################################
#
# load the user profile for a given user id
#

	my $self = shift;
	my ($userid) = @_;

	# store some dummy values, for real applications use a subclass
	$self->{userid} = $userid;
	$self->{profile}{username} = 'guest';
}

###########################################################
###
### module documentation
###
###########################################################
1;
__END__

=head1 NAME

CGI::Session::Auth - Authenticated sessions for CGI scripts

=head1 SYNOPSIS

  use CGI;
  use CGI::Session;
  use CGI::Session::Auth;

  # CGI object for headers, cookies, etc.
  my $cgi = new CGI;
  
  # CGI::Session object for session handling
  my $session = new CGI::Session(undef, $cgi, {Directory=>'/tmp'});
  
  # CGI::Session::Auth object for authentication
  my $auth = new CGI::Session::Auth({ CGI => $cgi, Session => $session });

  # check if visitor has already logged in
  if ($auth->loggedIn) {
  	showSecretPage;
  }
  else {
  	showLoginPage;
  }



=head1 DESCRIPTION

CGI::Session::Auth is a Perl class that provides the necessary
functions for authentication in CGI scripts. It uses CGI::Session
for session management and supports flat file and DBI database
backends.

CGI::Session::Auth offers an alternative approach to HTTP 
authentication. Its goal is to integrate the authentication
process into the web application as seamless as possible while keeping
the programming interface simple.

Users can authenticate themselves by entering their user
name and password into a login form. This is the most common way 
of authenticating a web site visitor.

Alternatively, a user can automatically be authenticated by his IP address.
This is useful when authorized users can't be bothered to log in manually
but can be identified by a range of fixed IP addresses.

CGI::Session::Auth manages a profile for every user account, 
containing his user name, his password and his user id. The user profile may 
contain additional fields for arbitrary data.


=head1 WARNING

This software is still in alpha status. It's meant only to show its basic functionality.
Features and interface are subject to change. If you want to use CGI::Session::Auth
in a production environment, please wait for version 1.0.



=head1 METHODS

=head2 new(\%parameters)

This is the class constructor. The hash referenced by C<\%parameters> must contain
the following key/value pairs:

=over 4

=item CGI

A reference to an CGI object.

=item Session

A reference to an CGI::Session object.

=back

Additionally, the following optional parameters are possible:

=over 4

=item DoIPAuth

Try to authenticate the visitor by his IP address. (Default: 0)

=item LoginVarPrefix

A string the names of the login form fields begin with. (Default. 'log_')

=back

=head2 init()

This method initializes the object and has to be called after object creation.
It fetches session information to determine the 
authentication status of the current visitor. C<init> further checks if form variables
from a proceeding login form have been set and eventually performs a login attempt.
If authentication succeeded neither by session data nor login information, and the
parameter C<DoIPAuth> is set to a true value, C<init> tries to authenticate the visitor by his 
IP address.

=head2 sessionCookie()

For the session to be persistent across page requests, its session ID has to be
stored in a cookie. This method returns the correct cookie (as generated by CGI::cookie()), 
but it remains the duty of the CGI application to send it.

=head2 loggedIn()

This method returns a boolean value representing the current visitors authentication 
status.

=head2 logout()

This method discards the current visitors authentication status.

=head2 checkUsername($username)

By this method can be checked if a certain user is logged in.

=head2 checkGroup($groupname)

By this method can be checked if the current user is a member of a certain user
group.

=head2 profile($key [, $value])

This accessor method returns the user profile field identified by C<$key>. If C<$value> is given,
it will be stored in the respective profile field first.



=head1 SEE ALSO

L<CGI::Session>

For further information (mailing lists, FAQ, etc.), see the module web site:
L<http://geewiz.teamlinux.de/projects/perl/cgi-session-auth>

=head1 AUTHOR

Jochen Lillich, E<lt>jl@teamlinux.deE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2003 by Jochen Lillich

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
