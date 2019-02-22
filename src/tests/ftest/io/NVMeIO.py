#!/usr/bin/python
'''
  (C) Copyright 2019 Intel Corporation.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
  The Government's rights to use, modify, reproduce, release, perform, display,
  or disclose this software are subject to the terms of the Apache License as
  provided in Contract No. B609815.
  Any reproduction of computer software, computer software documentation, or
  portions thereof marked with this legend must also reproduce the markings.
'''

import os
import sys
import json
import traceback
import uuid
import avocado

sys.path.append('./util')
sys.path.append('../util')
sys.path.append('../../../utils/py')
sys.path.append('./../../utils/py')
import ServerUtils
import WriteHostFile
import IorUtils

from GeneralUtils import DaosTestError
from daos_api import DaosContext, DaosPool, DaosContainer, DaosApiError, DaosLog

class ObjectMetadata(avocado.Test):
    """
    Test Class Description:
        Test the general Metadata operations and boundary conditions.
    """

    def setUp(self):
        self.pool = None
        self.hostlist = None
        self.hostfile_clients = None
        self.hostfile = None
        self.out_queue = None
        self.pool_connect = True
        
        with open('../../../.build_vars.json') as json_f:
            build_paths = json.load(json_f)

        self.basepath = os.path.normpath(build_paths['PREFIX']  + "/../")
        self.server_group = self.params.get("server_group",
                                            '/server/',
                                            'daos_server')
        self.context = DaosContext(build_paths['PREFIX'] + '/lib/')
        self.d_log = DaosLog(self.context)
        self.hostlist = self.params.get("servers", '/run/hosts/*')
        self.hostfile = WriteHostFile.WriteHostFile(self.hostlist, self.workdir)
        ServerUtils.runServer(self.hostfile, self.server_group, self.basepath)

    def tearDown(self):
        ServerUtils.stopServer(hosts=self.hostlist)

    def get_pool_size(self):
        return self.pool.pool_query()

    def verify_pool_size(self, original_pool_info, ior_args):
        current_pool_info = self.get_pool_size()
        if ior_args['stripe_size'] >= 4096:
            print("Size is > 4K so Data verification will be done with NVMe size")
            storage_index = 1
        else:
            print("Size is < 4K so Data verification will be done with SCM size")
            storage_index = 0

        free_pool_size = (original_pool_info.pi_space.ps_space.s_free[storage_index]
                          - current_pool_info.pi_space.ps_space.s_free[storage_index])
        expected_pool_size = ior_args['slots'] * ior_args['block_size']
        if free_pool_size < expected_pool_size:
            raise DaosTestError('Pool Free Size did not match Actual = {} Expected ={}'
                                .format(free_pool_size, expected_pool_size))

    @avocado.fail_on(DaosApiError)
    def test_nvme_IO(self):
        """
        Test ID: DAOS-1512
        Test Description: This test will verify 2000 IOR small size container after server restart.
                          Test will write IOR in 5 different threads for faster execution time.
                          Each thread will create 400 (8bytes) containers to the same pool.
                          Restart the servers, read IOR container file written previously and
                          validate data integrity by using IOR option "-R -G 1".
        :avocado: tags=nvme_io,large
        """
        total_ior_threads = 1
        ior_args = {}

        hostlist_clients = self.params.get("clients", '/run/hosts/*')
        slots = self.params.get("clientslots", '/run/ior/*')
        self.hostfile_clients = WriteHostFile.WriteHostFile(hostlist_clients, self.workdir, slots)

        for ior_seq in range(len(self.params.get("scmsize", '/run/ior/*'))):
            self.pool = DaosPool(self.context)
            self.pool.create(self.params.get("mode", '/run/pool/createmode/*'),
                             os.geteuid(),
                             os.getegid(),
                             self.params.get("scmsize", '/run/ior/*')[ior_seq],
                             self.params.get("setname", '/run/pool/createset/*'),
                             nvme_size=self.params.get("nvmesize", '/run/ior/*')[ior_seq])
            self.pool.connect(1 << 1)

            createsvc = self.params.get("svcn", '/run/pool/createsvc/')
            svc_list = ""
            for i in range(createsvc):
                svc_list += str(int(self.pool.svc.rl_ranks[i])) + ":"
            svc_list = svc_list[:-1]
    
            ior_args['client_hostfile'] = self.hostfile_clients
            ior_args['pool_uuid'] = self.pool.get_uuid_str()
            ior_args['svc_list'] = svc_list
            ior_args['basepath'] = self.basepath
            ior_args['server_group'] = self.server_group
            ior_args['tmp_dir'] = self.workdir
            ior_args['iorflags'] = self.params.get("iorflags", '/run/ior/*')
            ior_args['iteration'] = self.params.get("iteration", '/run/ior/*')
            ior_args['stripe_size'] = self.params.get("stripesize", '/run/ior/*')[ior_seq]
            ior_args['block_size'] = self.params.get("blocksize", '/run/ior/*')[ior_seq]
            ior_args['stripe_count'] = self.params.get("stripecount", '/run/ior/*')
            ior_args['async_io'] = self.params.get("asyncio", '/run/ior/*')
            ior_args['object_class'] = self.params.get("objectclass", '/run/ior/*')
            ior_args['slots'] = self.params.get("clientslots", '/run/ior/*')
    
            try:
                for i in range(total_ior_threads):
                    size_before_ior = self.get_pool_size()
                    IorUtils.run_ior(ior_args['client_hostfile'],
                                     ior_args['iorflags'],
                                     ior_args['iteration'],
                                     ior_args['block_size'],
                                     ior_args['stripe_size'],
                                     ior_args['pool_uuid'],
                                     ior_args['svc_list'],
                                     ior_args['stripe_size'],
                                     ior_args['stripe_size'],
                                     ior_args['stripe_count'],
                                     ior_args['async_io'],
                                     ior_args['object_class'],
                                     ior_args['basepath'],
                                     ior_args['slots'],
                                     filename=str(uuid.uuid4()),
                                     display_output=True)
                    self.verify_pool_size(size_before_ior, ior_args)
            except Exception as exe:
                print (exe)
                print (traceback.format_exc())
                self.fail()

            try:
                if self.pool_connect:
                    self.pool.disconnect()
                if self.pool:
                    self.pool.destroy(1)
            except:
                self.fail("Failed to Dstroy/Disconnect the Pool")
                