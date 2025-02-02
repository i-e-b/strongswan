/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "mac_signer.h"

typedef struct private_signer_t private_signer_t;

/**
 * Private data of a mac_signer_t object.
 */
struct private_signer_t {

	/**
	 * Public interface
	 */
	signer_t public;

	/**
	 * MAC to use
	 */
	mac_t *mac;

	/**
	 * Truncation of MAC output
	 */
	size_t truncation;
};

METHOD(signer_t, get_signature, bool,
	private_signer_t *this, chunk_t data, uint8_t *buffer)
{
	if (buffer)
	{
		uint8_t mac[this->mac->get_mac_size(this->mac)];

		if (!this->mac->get_mac(this->mac, data, mac))
		{
			return FALSE;
		}
		memcpy(buffer, mac, this->truncation);
		return TRUE;
	}
	return this->mac->get_mac(this->mac, data, NULL);
}

METHOD(signer_t, allocate_signature, bool,
	private_signer_t *this, chunk_t data, chunk_t *chunk)
{
	if (chunk)
	{
		uint8_t mac[this->mac->get_mac_size(this->mac)];

		if (!this->mac->get_mac(this->mac, data, mac))
		{
			return FALSE;
		}
		*chunk = chunk_alloc(this->truncation);
		memcpy(chunk->ptr, mac, this->truncation);
		return TRUE;
	}
	return this->mac->get_mac(this->mac, data, NULL);
}

METHOD(signer_t, verify_signature, bool,
	private_signer_t *this, chunk_t data, chunk_t signature)
{
    int size = this->mac->get_mac_size(this->mac);
	uint8_t mac[size];

    DBG1(DBG_LIB, "verify_signature (src/libstrongswan/crypto/signers/mac_signer.c:79)\nData input => %B", &data);

	if (signature.len != this->truncation)
	{
		return FALSE;
	}
	int ok = this->mac->get_mac(this->mac, data, mac);

    if (ok){
        DBG1(DBG_LIB, "MAC verification self calculate OK");
    } else {
        DBG1(DBG_LIB, "MAC verification self calculate FAILED");
        return FALSE;
    }

    DBG1(DBG_LIB, "-------------EXPECTED-------------");
    char buf[100];char* curs = buf;for (int i = 0; i < 100; i++) buf[i]=0;
    for (int i = 0; i < 16; i++){ sprintf(curs, " %02x", mac[i]); curs += 3; }
    DBG1(DBG_LIB, buf);

    DBG1(DBG_LIB, "-------------ACTUAL-------------");
    curs = buf;for (int i = 0; i < 100; i++) buf[i]=0;
    for (int i = 0; i < 16; i++){ sprintf(curs, " %02x", signature.ptr[i]); curs += 3; }
    DBG1(DBG_LIB, buf);


    return ok && memeq_const(signature.ptr, mac, this->truncation);
}

METHOD(signer_t, get_key_size, size_t,
	private_signer_t *this)
{
	return this->mac->get_mac_size(this->mac);
}

METHOD(signer_t, get_block_size, size_t,
	private_signer_t *this)
{
	return this->truncation;
}

METHOD(signer_t, set_key, bool,
	private_signer_t *this, chunk_t key)
{
	return this->mac->set_key(this->mac, key);
}

METHOD(signer_t, destroy, void,
	private_signer_t *this)
{
	this->mac->destroy(this->mac);
	free(this);
}

/*
 * Described in header
 */
signer_t *mac_signer_create(mac_t *mac, size_t len)
{
	private_signer_t *this;

	INIT(this,
		.public = {
			.get_signature = _get_signature,
			.allocate_signature = _allocate_signature,
			.verify_signature = _verify_signature,
			.get_block_size = _get_block_size,
			.get_key_size = _get_key_size,
			.set_key = _set_key,
			.destroy = _destroy,
		},
		.truncation = min(len, mac->get_mac_size(mac)),
		.mac = mac,
	);

	return &this->public;
}
