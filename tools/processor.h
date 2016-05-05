/**
 * Copyright 2014 Context Information Security
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <stdio.h>

#if defined __cplusplus


//! Base for double-ended processing.
struct processor
{
    virtual ~processor() {}
    /** \brief          Process data from the client
     *  \param  data    Data to process
     *  \param  len     Number of bytes to process
     *  \return false   Processing failed
     *  \return true    Processing successful
     */
    virtual bool client(const uint8_t *data, size_t len) = 0 ;
    /** \brief          Process data from the server
     *  \param  data    Data to process
     *  \param  len     Number of bytes to process
     *  \return false   Processing failed
     *  \return true    Processing successful
     */
    virtual bool server(const uint8_t *data, size_t len) = 0 ;
} ;


#endif

#endif
