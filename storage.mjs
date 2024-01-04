#!/usr/bin/node

import assert from 'node:assert';
import * as fs from 'node:fs';
import { dirname, resolve as path_resolve, join as path_join } from 'node:path';
import * as readline from 'node:readline/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import proper_lockfile from 'proper-lockfile';
import { api as sodium } from 'sodium';
import Getopt from 'node-getopt';

import { inspect } from 'util';

Buffer.prototype[ inspect.custom ] = function( depth, options ) {
	return options.stylize( 'h', 'special' ) +
		options.stylize( '`' + this.toString('hex') + '`', 'string' );
};

inspect.defaultOptions.breakLength = 112;

const { log } = console;

const die = ( ...args ) => {
	assert( typeof args[0] === 'string' );
	args[0] = `\x1b[1;31m${ args[0] }\x1b[m`;
	console.error( ...args );
	process.exit( 1 );
};

const question = async ( s ) => {
	const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
	try {
		return await rl.question( s );
	} finally {
		rl.close();
	}
};


//============== filesystem utils ==============================================================================

const is_iterable = x => typeof x?.[ Symbol.iterator ] === 'function';

const rmfv = ( ...paths ) => {
	for( let path of paths ) {
		if( ! fs.existsSync( path ) )
			continue;
		log( `Removing ${path}` );
		fs.rmSync( path );
	}
};

const dirent_iterator = function*( path ) {
	let d = fs.opendirSync( path );
	try {
		let ent;
		while( ( ent = d.readSync() ) !== null ) {
			if( ent.name === '.' || ent.name === '..' )
				continue;
			ent.path = path_join( path, ent.name );
			yield ent;
		}
	} finally {
		d.closeSync();
	}
};

const dir_is_empty = ( path ) => {
	for( let ent of dirent_iterator( path ) )
		return false;
	return true;
};

const try_read_file = ( path, encoding, postprocess ) => {
	try {
		let data = fs.readFileSync( path, encoding );
		return postprocess ? postprocess( data ) : data;
	} catch( err ) {
		if( err.code === 'ENOENT' )
			return null;
		throw err;
	}
};

const dir_fds = Object.create( null );

// we're not long-running so I don't care about leaking these fds
const get_dir_fd = ( path ) => {
	let fd = dir_fds[ path ];
	if( fd === undefined )
		dir_fds[ path ] = fd = fs.openSync( path );
	return fd;
};

const mkdir_safe = ( path ) => {
	if( ! fs.statSync( path, { throwIfNoEntry: false } )?.isDirectory() ) {
		let dir_fd = get_dir_fd( dirname( path ) );
		fs.mkdirSync( path );
		fs.fsyncSync( dir_fd );
		log( `Created directory ${path}` );
	}
	return path;
};

const write_file_safe = ( path, data, use_tmp=true, mode ) => {
	log( `Writing ${path}` );
	let dir_fd = get_dir_fd( dirname( path ) );
	let tmp_path = path;
	if( use_tmp )
		tmp_path += '.tmp';
	let fd = fs.openSync( tmp_path, 'w', mode );
	try {
		fs.writeFileSync( fd, data );
		fs.fsyncSync( fd );
		fs.closeSync( fd );
		fd = -1;
		if( use_tmp )
			fs.renameSync( tmp_path, path );
	} catch( err ) {
		if( fd >= 0 ) {
			try { fs.closeSync( fd ); } catch( err ) {}
		}
		try { fs.rmSync( tmp_path ); } catch( err ) {}
		throw err;
	}
	fs.fsyncSync( dir_fd );
};


//============== file paths ====================================================================================

const package_dir = fs.realpathSync( dirname( fileURLToPath( import.meta.url ) ) );

const files_dir = path_join( package_dir, 'encrypted-files' );

const index_file = path_join( package_dir, 'files-index.json' );
const pubkey_file = path_join( package_dir, 'public-key' );
const privkey_file = path_join( package_dir, 'unlocked-key' );
const encprivkey_file = path_join( package_dir, 'locked-key.json' );
const pw_img_file = path_join( package_dir, 'password.png' );


//============== acquire lock on state =========================================================================
//
// protect against user accidently running two operations at the same time

const state_lock = proper_lockfile.lockSync( package_dir, {
	realpath: false,  // already done
	lockFilePath: path_join( package_dir, '.state-lock' ),
});


//============== cryptography ==================================================================================

const randombuf = ( len ) => {
	let buf = Buffer.alloc( len );
	sodium.randombytes_buf( buf );
	return buf;
};

const pklen = sodium.crypto_box_PUBLICKEYBYTES;
const sklen = sodium.crypto_box_SECRETKEYBYTES;
const skpklen = sklen + pklen;

let pubkey = try_read_file( pubkey_file );
if( pubkey && pubkey.length !== pklen ) {
	log( `Public key has invalid length` );
	pubkey = null;
}
let privkey = null;

const set_privkey = ( skpk ) => {
	if( skpk.length !== skpklen )
		return log( `Private key has invalid length` ), false;
	let sk = skpk.subarray( 0, sklen );
	let pk = skpk.subarray( sklen );
	if( ! sodium.crypto_scalarmult_base( sk ).equals( pk ) )
		return log( `Private key is invalid` ), false;
	if( ! pubkey )
		pubkey = pk;
	else if( ! pubkey.equals( pk ) )
		return log( `Private key does not match public key` ), false;
	privkey = sk;
	return true;
};
try_read_file( privkey_file, null, set_privkey );


let encprivkey = try_read_file( encprivkey_file, 'utf8', JSON.parse );


let index = try_read_file( index_file, 'utf8', JSON.parse ) || [];
let index_map = new Map;
for( let n = 0; n < index.length; ++n ) {
	if( ! index[ n ] )
		continue;
	let { path } = index[ n ];
	if( index_map.has( path ) )
		die( `Duplicate path in index:`, path );
	index_map.set( path, n );
}


//==============================================================================================================

let { argv: args, options: opt } = Getopt.create([
	[ 'c', 'clean',		'remove storage keys/index provided it contains no files' ],
	[ '',  'force-clean',	'unconditionally remove storage including files' ],
	[ 'i', 'init',		'initialize storage if not already initialized' ],
	[ 'u', 'unlock',	'unlock storage and clear password protection' ],
	[ 'p', 'prelock',	'setup password protection (if not already done) but leave storage unlocked' ],
	[ 'L', 'lock',		'setup password protection (if not already done) and lock storage' ],
	[ '',  'add',		'add files to storage (default)' ],
	[ 'l', 'list',		'list files in storage' ],
	[ 'r', 'restore',	'restore files from storage' ],
	[ 'R', 'remove',	'remove files from storage' ],
	[ 'a', 'all',		'list/restore/remove all files (default for --list)' ],
	[ 'h', 'help',		'display this help' ],
]).bindHelp().parseSystem();

if( opt.add && ( opt.list || opt.restore || opt.remove ) )
	die( `Cannot combine --add with --list, --restore, or --remove` );
if( opt.add && ! args.length )
	die( `--add requires one or more file path arguments` );
if( args.length && !( opt.list || opt.restore || opt.remove ) )
	opt.add = true;
if( opt.all && !( opt.list || opt.restore || opt.remove ) )
	die( `--all requires --list, --restore, or --remove` );
if( opt.list && ! args.length )
	opt.all = true;
if( opt.restore && ! args.length && ! opt.all )
	die( `--restore requires one or more file path arguments or --all` );
if( opt.remove && ! args.length && ! opt.all )
	die( `--remove requires one or more file path arguments or --all` );
if( opt.all && args.length )
	die( `Cannot combine --all with explicit file path arguments` );

mkdir_safe( files_dir );

const no_privkey = () => !( privkey || encprivkey );

if( opt.clean || opt['force-clean'] ) {
	if( ! dir_is_empty( files_dir ) ) {
		if( no_privkey() )
			log( 'Removing non-empty storage since private key is missing' );
		else if( ! index.length )
			log( 'Removing non-empty storage since index is missing' );
		else if( opt['force-clean'] )
			log( 'Removing non-empty storage due to --force-clean' );
		else
			die( 'Refusing to remove non-empty storage without --force-clean' );
	}
	rmfv( index_file, privkey_file, encprivkey_file, pubkey_file, pw_img_file );
	index = [];
	index_map = new Map;
	pubkey = privkey = encprivkey = null;
	for( let { path } of dirent_iterator( files_dir ) )
		rmfv( path );
}

if( no_privkey() ) {
	if( index.length )
		die( 'Storage is non-empty (according to index) but private key is missing' );

	if( opt.init ) {
		rmfv( pubkey_file, pw_img_file );
		( { secretKey: privkey, publicKey: pubkey } = sodium.crypto_box_keypair() );

		opt.unlock = true;
	}
}

while( ( opt.unlock || opt.prelock || opt.restore ) && ! privkey ) {
	if( ! encprivkey )
		die( `Cannot unlock storage since there's no encrypted private key` );
	let { pwlen, alg, opslimit, memlimit, salt, data } = encprivkey;
	let pw = await question( 'Password: ' );
	log( `\x1b[FPassword: ${pw.replaceAll( /\S/g, '*' )}` );
	pw = pw.replaceAll( /\s+/g, '' );
	if( pw.length !== 4 * pwlen ) {
		log( `Password has incorrect length (expecting ${pwlen} * 4 chars)` );
		continue;
	}
	if( /[^0-9A-Za-z+\/]/.test( pw ) ) {
		log( `Password contains invalid character` );
		continue;
	}
	pw = Buffer.from( pw, 'base64' );
	salt = Buffer.from( salt, 'base64' );
	data = Buffer.from( data, 'base64' );
	let tmp = sodium.crypto_pwhash( skpklen, pw, salt, opslimit, memlimit, alg );
	for( let i = 0; i < skpklen; ++i )
		data[i] ^= tmp[i];
	if( ! set_privkey( data ) ) {
		log( `Password incorrect` );
		continue;
	}
	log( `Password OK` );
}

assert( pubkey || ! privkey );

if( ( opt.unlock || opt.prelock ) && ! fs.existsSync( privkey_file ) )
	write_file_safe( privkey_file, Buffer.concat( [ privkey, pubkey ] ) );

if( opt.unlock ) {
	rmfv( encprivkey_file, pw_img_file );
	encprivkey = null;
}

if( ( opt.prelock || opt.lock ) && ! encprivkey ) {
	if( ! privkey )
		die( `Cannot lock storage since there's no private key (use --init ?)` );
	let pwlen = 4;  // number of groups of 4 chars (after base64)
	let pw = randombuf( pwlen * 3 );
	let alg = sodium.crypto_pwhash_ALG_DEFAULT;
	let opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
	let memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
	let salt = randombuf( sodium.crypto_pwhash_SALTBYTES );
	let tmp = sodium.crypto_pwhash( skpklen, pw, salt, opslimit, memlimit, alg );
	let data = Buffer.concat( [ privkey, pubkey ] );
	for( let i = 0; i < skpklen; ++i )
		data[i] ^= tmp[i];
	salt = salt.toString( 'base64' );
	data = data.toString( 'base64' );
	encprivkey = { pwlen, alg, opslimit, memlimit, salt, data };
	pw = pw.toString( 'base64' ).replaceAll( /(\S{4})/g, '$1 ' ).trim();
	rmfv( encprivkey_file, pw_img_file );
	write_file_safe( pw_img_file, execFileSync( 'qrencode', [ '-o-', '-s10', '-lM', '-m8' ],
			{ input: pw, stdio: [ 'pipe', 'pipe', 'inherit' ], timeout: 1000 }) );
	write_file_safe( encprivkey_file, JSON.stringify( encprivkey ) );
}

if( pubkey && ! fs.existsSync( pubkey_file ) )
	write_file_safe( pubkey_file, pubkey );

if( opt.list || opt.restore || opt.remove ) {
	let filter;
	if( ! opt.all ) {
		filter = new Set;
		for( let arg of args ) {
			if( arg === `${ arg >>> 0 }` ) {
				let n = +arg;
				if( n >= index.length || ! index[ n ] ) {
					log( "File not in index (skipping):", n );
					continue;
				}
				filter.add( n );
			} else {
				let path = path_resolve( arg );
				let n = index_map.get( path );
				if( n === undefined ) {
					log( "File path not in index (skipping):", path );
					continue;
				}
				filter.add( n );
			}
		}
	} else if( ! index.length ) {
		log( `No files in storage` );
		process.exit(0);
	}

	if( opt.restore && ! privkey )  // shouldn't be possible, it would have failed earlier in this script
		die( `Private key missing` );

	const filemode_stringify = ( mode ) =>
		"-r"[ mode >> 8 & 1 ] +
		"-w"[ mode >> 7 & 1 ] +
		"-xSs"[ ( mode >> 6 & 1 ) | ( mode >> 10 & 2 ) ] +
		"-r"[ mode >> 5 & 1 ] +
		"-w"[ mode >> 4 & 1 ] +
		"-xSs"[ ( mode >> 3 & 1 ) | ( mode >> 9 & 2 ) ] +
		"-r"[ mode >> 2 & 1 ] +
		"-w"[ mode >> 1 & 1 ] +
		"-xTt"[ ( mode >> 0 & 1 ) | ( mode >> 8 & 2 ) ];

	let write_index = false;
	for( let n of Array.from( filter ?? index_map.values() ).sort() ) {
		let { path, mode, nonce, epk } = index[ n ];
		let enc_path = path_join( files_dir, `${n}` );
		if( ! fs.existsSync( enc_path ) ) {
			log( `Missing file:`, enc_path );
			index[ n ] = null;
			index_map.delete( path );
			write_index = true;
			continue;
		}
		if( opt.list ) {
			let { size } = fs.statSync( enc_path );
			size -= sodium.crypto_box_MACBYTES;
			log( n, filemode_stringify( mode ), size, path );
		}
		if( opt.restore ) {
			nonce = Buffer.from( nonce, 'base64' );
			epk = Buffer.from( epk, 'base64' );
			let data = fs.readFileSync( enc_path );
			data = sodium.crypto_box_open_easy( data, nonce, epk, privkey );
			let curdata = try_read_file( path );
			if( ! curdata )
				write_file_safe( path, data, false, mode );
			else if( curdata.equals( data ) )
				log( 'File already intact:', path );
			else
				die( 'File already exists:', path );
		}
		if( opt.remove ) {
			rmfv( enc_path );
			index[ n ] = null;
			index_map.delete( path );
			write_index = true;
		}
	}
	if( write_index ) {
		while( index.length > 0 && index.at( -1 ) === null )
			index.pop();
		write_file_safe( index_file, JSON.stringify( index ) );
	}
}

if( opt.lock ) {
	assert( encprivkey );
	rmfv( privkey_file );
	privkey = null;
}

if( opt.add ) {
	if( ! pubkey )
		die( `Cannot add files to storage since there's no public key (use --init ?)` );

	while( args.length ) {
		let path = path_resolve( args.shift() );
		let stat = fs.statSync( path );
		if( ! stat.isFile() )
			die( `Not a file:`, path );

		if( index_map.has( path ) )
			die( `Path already in index:`, path );  // FIXME, ask to replace

		let nonce = randombuf( sodium.crypto_box_NONCEBYTES );
		let { secretKey: esk, publicKey: epk } = sodium.crypto_box_keypair();
		let data = sodium.crypto_box_easy( fs.readFileSync( path ), nonce, pubkey, esk );
		let n = index.length;
		nonce = nonce.toString( 'base64' );
		epk = epk.toString( 'base64' );
		index[ n ] = { path, mode: stat.mode, nonce, epk };
		index_map.set( path, n );
		write_file_safe( path_join( files_dir, `${n}` ), data );
		write_file_safe( index_file, JSON.stringify( index ) );
		rmfv( path );
	}
}
