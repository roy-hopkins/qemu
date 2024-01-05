/*
 * Copyright (c) 2023 SUSE
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef EXEC_IGVM_H
#define EXEC_IGVM_H

#include "exec/confidential-guest-support.h"

#if defined(CONFIG_IGVM)

void igvm_file_init(ConfidentialGuestSupport *cgs);
void igvm_process(ConfidentialGuestSupport *cgs);

#else

static inline void igvm_file_init(ConfidentialGuestSupport *cgs)
{
}

static inline void igvm_process(ConfidentialGuestSupport *cgs)
{
}

#endif

#endif