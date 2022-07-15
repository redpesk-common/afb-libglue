###########################################################################
# Copyright 201 IoT.bzh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###########################################################################

PROJECT_TARGET_ADD(afb-glue)

	# Define project Targets
    add_library(${TARGET_NAME} SHARED glue-afb.c  utils-glue.c)

	SET_TARGET_PROPERTIES(${TARGET_NAME} PROPERTIES
		OUTPUT_NAME ${TARGET_NAME}
		VERSION ${PROJECT_VERSION}
		SOVERSION ${PROJECT_VERSION_MAJOR}
	)

    INSTALL(FILES glue-afb.h  glue-utils.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    INSTALL(TARGETS ${TARGET_NAME}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )

