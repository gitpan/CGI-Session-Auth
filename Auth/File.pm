###########################################################
# CGI::Session::Auth::File
# Authenticated sessions for CGI scripts
# Copyright (c) 2003 Jochen Lillich <jl@teamlinux.de>
###########################################################
#
# $Id: File.pm,v 1.1 2003/10/31 08:28:33 jlillich Exp $
#

package CGI::Session::Auth::File;
use base qw(CGI::Session::Auth);

use 5.008;
use strict;
use warnings;
use Carp;

our $VERSION = do { my @r = (q$Revision: 1.1 $ =~ /\d+/g); sprintf "%d." . "%03d" x (scalar @r - 1), @r; };

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
    
	# parameter 'UserFile': file containing user data
	$self->{userfile}  = $params->{UserFile} || 'auth_user.txt';
	# parameter 'GroupFile': file containing group data
	$self->{groupfile} = $params->{GroupFile} || 'auth_group.txt';
    
    #
    # class members
    #

	# array of registered users, each element is an anon hash of user attributes
	$self->{users} = [];
	# array of groups, each element is an anon array of user names
	$self->{groups} = [];
	    
    # blessed are the greek
    bless($self, $class);

	# read authentication data
	$self->_readFiles();
	    
    return $self;
}

###########################################################
###
### backend specific methods
###
###########################################################

###########################################################

sub _login {
}

###########################################################

sub _ipAuth {
}

###########################################################

sub _loadProfile {
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

sub _readFiles {
	my $self = shift;
	
	open(USER, '<' . $self->{userfile}) or croak "Could not open user file";
	# get field names from first line
	my $fieldlist = <USER>;
	my @fieldnames = split(':', $fieldlist);
	# get user records
	while (my $record = <USER>) {
		my @fields = split(':', $record);
		# store fields in hash
		my $entry = {};
		foreach (@fieldnames) {
			$entry->{$_} = shift @fields;
		}
		# store hash
		push @{$self->{users}}, $entry;
	}
	close(USER);
	
}

1;
__END__
