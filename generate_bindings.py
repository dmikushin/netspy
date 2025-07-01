#!/usr/bin/env python3
"""
Generate C++ bindings from network function prototypes stored in JSON.
This script reads a JSON file containing network function prototypes and
generates C++ code for function pointer declarations, loading, and
interception methods.
"""

import json
import sys
import os

def generate_function_pointer_types(functions):
    """Generate typedefs for function pointers."""
    result = []
    for func in functions:
        return_type = func["return_type"]
        name = func["name"]
        params = ", ".join([f"{param['type']} {param['name']}" for param in func["parameters"]])

        # Create typedef for function pointer
        result.append(f"typedef {return_type} (*{name}_func_t)({params});")

    return "\n".join(result)

def generate_function_pointer_declarations(functions):
    """Generate declarations for function pointers (header)."""
    result = []
    for func in functions:
        name = func["name"]
        result.append(f"static {name}_func_t real_{name};")
    return "\n".join(result)

def generate_function_pointer_definitions(functions):
    """Generate definitions for function pointers (implementation)."""
    result = []
    for func in functions:
        name = func["name"]
        result.append(f"{name}_func_t NetworkInterceptor::real_{name} = nullptr;")
    return "\n".join(result)

def generate_function_loading(functions):
    """Generate code to load original functions using dlsym."""
    result = []
    for func in functions:
        name = func["name"]
        result.append(f'    real_{name} = reinterpret_cast<{name}_func_t>(dlsym(RTLD_NEXT, "{name}"));')
        result.append(f'    if (!real_{name}) {{')
        result.append(f'        fprintf(stderr, "Error: Failed to load {name} function: %s\\n", dlerror());')
        result.append(f'        exit(1);')
        result.append(f'    }}')

    return "\n".join(result)

def generate_function_interceptors(functions):
    """Generate global function interceptors."""
    result = []
    for func in functions:
        return_type = func["return_type"]
        name = func["name"]
        params_decl = ", ".join([f"{param['type']} {param['name']}" for param in func["parameters"]])
        params_call = ", ".join([f"{param['name']}" for param in func["parameters"]])

        result.append(f"extern \"C\" {return_type} {name}({params_decl}) {{")
        result.append(f"    return NetworkInterceptor::getInstance().intercept_{name}({params_call});")
        result.append("}\n")

    return "\n".join(result)

def generate_interceptor_methods_declarations(functions):
    """Generate method declarations for NetworkInterceptor class."""
    result = []
    for func in functions:
        return_type = func["return_type"]
        name = func["name"]
        params_decl = ", ".join([f"{param['type']} {param['name']}" for param in func["parameters"]])

        result.append(f"    {return_type} intercept_{name}({params_decl});")

    return "\n".join(result)

def generate_interceptor_methods(functions):
    """Generate method implementations for NetworkInterceptor class."""
    result = []
    for func in functions:
        return_type = func["return_type"]
        name = func["name"]
        params_decl = ", ".join([f"{param['type']} {param['name']}" for param in func["parameters"]])
        params_call = ", ".join([f"{param['name']}" for param in func["parameters"]])

        result.append(f"{return_type} NetworkInterceptor::intercept_{name}({params_decl}) {{")

        # Add logging and interception logic based on function
        if name == "socket":
            result.append(f"    int sockfd = real_{name}({params_call});")
            result.append("    if (sockfd >= 0 && sockfd < MAX_SOCKETS) {")
            result.append("        std::lock_guard<std::mutex> lock(m_socketMutex);")
            result.append("        m_socketInfo[sockfd].domain = domain;")
            result.append("        m_socketInfo[sockfd].type = type;")
            result.append("        m_socketInfo[sockfd].protocol = protocol;")
            result.append("        m_socketInfo[sockfd].isConnected = false;")
            result.append("        m_socketInfo[sockfd].localAddr = {};")
            result.append("        m_socketInfo[sockfd].remoteAddr = {};")
            result.append("        debug(\"socket(%d, %d, %d) = %d\\n\", domain, type, protocol, sockfd);")
            result.append("    }")
            result.append("    return sockfd;")
        elif name == "bind":
            result.append(f"    int ret = real_{name}({params_call});")
            result.append("    if (ret == 0 && sockfd >= 0 && sockfd < MAX_SOCKETS) {")
            result.append("        updateSocketInfo(sockfd, addr, true);")
            result.append("        if (addr->sa_family == AF_INET) {")
            result.append("            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;")
            result.append("            debug(\"bind(%d, %s:%d) = %d\\n\", sockfd, ")
            result.append("                  inet_ntoa(addr_in->sin_addr), ")
            result.append("                  ntohs(addr_in->sin_port), ret);")
            result.append("        } else {")
            result.append("            debug(\"bind(%d, family=%d) = %d\\n\", sockfd, addr->sa_family, ret);")
            result.append("        }")
            result.append("    }")
            result.append("    return ret;")
        elif name == "connect":
            result.append("    if (sockfd >= 0 && sockfd < MAX_SOCKETS) {")
            result.append("        socklen_t local_addrlen = sizeof(struct sockaddr_storage);")
            result.append("        if (getsockname(sockfd, (struct sockaddr *)&m_socketInfo[sockfd].localAddr, &local_addrlen) != 0) {")
            result.append("            m_socketInfo[sockfd].localAddr = {};")
            result.append("        }")
            result.append("    }")
            result.append(f"    int ret = real_{name}({params_call});")
            result.append("    if (sockfd >= 0 && sockfd < MAX_SOCKETS) {")
            result.append("        if (ret == 0 || (ret == -1 && errno == EINPROGRESS)) {")
            result.append("            updateSocketInfo(sockfd, addr, false);")
            result.append("            if (addr->sa_family == AF_INET) {")
            result.append("                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;")
            result.append("                debug(\"connect(%d, %s:%d) = %d\\n\", sockfd, ")
            result.append("                      inet_ntoa(addr_in->sin_addr), ")
            result.append("                      ntohs(addr_in->sin_port), ret);")
            result.append("            } else {")
            result.append("                debug(\"connect(%d, family=%d) = %d\\n\", sockfd, addr->sa_family, ret);")
            result.append("            }")
            result.append("        }")
            result.append("        socklen_t local_addrlen = sizeof(struct sockaddr_storage);")
            result.append("        if (getsockname(sockfd, (struct sockaddr *)&m_socketInfo[sockfd].localAddr, &local_addrlen) != 0) {")
            result.append("            m_socketInfo[sockfd].localAddr = {};")
            result.append("        }")
            result.append("    }")
            result.append("    return ret;")
        elif name in ["accept", "accept4"]:
            param_list = params_call
            if name == "accept4":
                flags_param = ", flags"
            else:
                flags_param = ""

            result.append(f"    int new_sockfd = real_{name}({params_call});")
            result.append("    if (new_sockfd >= 0 && new_sockfd < MAX_SOCKETS) {")
            result.append("        std::lock_guard<std::mutex> lock(m_socketMutex);")
            result.append("        if (sockfd >= 0 && sockfd < MAX_SOCKETS) {")
            result.append("            m_socketInfo[new_sockfd].domain = m_socketInfo[sockfd].domain;")
            result.append("            m_socketInfo[new_sockfd].type = m_socketInfo[sockfd].type;")
            result.append("            m_socketInfo[new_sockfd].protocol = m_socketInfo[sockfd].protocol;")
            result.append("        } else {")
            result.append("            m_socketInfo[new_sockfd].domain = AF_INET;")
            result.append("            m_socketInfo[new_sockfd].type = SOCK_STREAM;")
            result.append("            m_socketInfo[new_sockfd].protocol = 0;")
            result.append("        }")
            result.append("        m_socketInfo[new_sockfd].isConnected = true;")
            result.append("        socklen_t local_addrlen = sizeof(struct sockaddr_storage);")
            result.append("        if (getsockname(new_sockfd, (struct sockaddr *)&m_socketInfo[new_sockfd].localAddr, &local_addrlen) != 0) {")
            result.append("            m_socketInfo[new_sockfd].localAddr = {};")
            result.append("        }")
            result.append("        if (addr && addrlen) {")
            result.append("            m_socketInfo[new_sockfd].remoteAddr = {};")
            result.append("            memcpy(&m_socketInfo[new_sockfd].remoteAddr, addr, *addrlen);")
            result.append("        }")
            result.append("        if (addr && addr->sa_family == AF_INET) {")
            result.append("            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;")
            result.append(f"            debug(\"{name}(%d{flags_param}) = %d from %s:%d\\n\", sockfd, new_sockfd,")
            result.append("                  inet_ntoa(addr_in->sin_addr), ")
            result.append("                  ntohs(addr_in->sin_port));")
            result.append("        } else {")
            result.append(f"            debug(\"{name}(%d{flags_param}) = %d\\n\", sockfd, new_sockfd);")
            result.append("        }")
            result.append("    }")
            result.append("    return new_sockfd;")
        elif name in ["send", "write"]:
            if name == "send":
                fd_param = "sockfd"
                debug_param = ", flags"
            else:
                fd_param = "fd"
                debug_param = ""

            result.append(f"    ssize_t ret = real_{name}({params_call});")
            result.append(f"    if (ret > 0 && {fd_param} >= 0 && {fd_param} < MAX_SOCKETS) {{")
            result.append("        std::lock_guard<std::mutex> lock(m_socketMutex);")
            result.append(f"        bool is_socket = m_socketInfo[{fd_param}].domain != 0;")
            result.append("        if (is_socket) {")
            result.append(f"            logNetworkActivity({fd_param}, buf, ret, true);")
            result.append(f"            debug(\"{name}(%d, len=%zu{debug_param}) = %zd\\n\", {fd_param}, {('len' if name == 'send' else 'count')}{debug_param}, ret);")
            result.append("        }")
            result.append("    }")
            result.append("    return ret;")
        elif name in ["recv", "read"]:
            if name == "recv":
                fd_param = "sockfd"
                debug_param = ", flags"
            else:
                fd_param = "fd"
                debug_param = ""

            result.append(f"    ssize_t ret = real_{name}({params_call});")
            result.append(f"    if (ret > 0 && {fd_param} >= 0 && {fd_param} < MAX_SOCKETS) {{")
            result.append("        std::lock_guard<std::mutex> lock(m_socketMutex);")
            result.append(f"        bool is_socket = m_socketInfo[{fd_param}].domain != 0;")
            result.append("        if (is_socket) {")
            result.append(f"            logNetworkActivity({fd_param}, buf, ret, false);")
            result.append(f"            debug(\"{name}(%d, len=%zu{debug_param}) = %zd\\n\", {fd_param}, {('len' if name == 'recv' else 'count')}{debug_param}, ret);")
            result.append("        }")
            result.append("    }")
            result.append("    return ret;")
        elif name == "sendto":
            result.append(f"    ssize_t ret = real_{name}({params_call});")
            result.append("    if (ret > 0 && sockfd >= 0 && sockfd < MAX_SOCKETS) {")
            result.append("        if (dest_addr) {")
            result.append("            updateSocketInfo(sockfd, dest_addr, false);")
            result.append("        }")
            result.append("        logNetworkActivity(sockfd, buf, ret, true);")
            result.append("        if (dest_addr && dest_addr->sa_family == AF_INET) {")
            result.append("            struct sockaddr_in *addr_in = (struct sockaddr_in *)dest_addr;")
            result.append("            debug(\"sendto(%d, len=%zu, %s:%d) = %zd\\n\", sockfd, len,")
            result.append("                  inet_ntoa(addr_in->sin_addr), ")
            result.append("                  ntohs(addr_in->sin_port), ret);")
            result.append("        } else {")
            result.append("            debug(\"sendto(%d, len=%zu) = %zd\\n\", sockfd, len, ret);")
            result.append("        }")
            result.append("    }")
            result.append("    return ret;")
        elif name == "recvfrom":
            result.append(f"    ssize_t ret = real_{name}({params_call});")
            result.append("    if (ret > 0 && sockfd >= 0 && sockfd < MAX_SOCKETS) {")
            result.append("        if (src_addr) {")
            result.append("            updateSocketInfo(sockfd, src_addr, false);")
            result.append("        }")
            result.append("        logNetworkActivity(sockfd, buf, ret, false);")
            result.append("        if (src_addr && src_addr->sa_family == AF_INET) {")
            result.append("            struct sockaddr_in *addr_in = (struct sockaddr_in *)src_addr;")
            result.append("            debug(\"recvfrom(%d, len=%zu, %s:%d) = %zd\\n\", sockfd, len,")
            result.append("                  inet_ntoa(addr_in->sin_addr), ")
            result.append("                  ntohs(addr_in->sin_port), ret);")
            result.append("        } else {")
            result.append("            debug(\"recvfrom(%d, len=%zu) = %zd\\n\", sockfd, len, ret);")
            result.append("        }")
            result.append("    }")
            result.append("    return ret;")
        elif name == "close":
            result.append(f"    int ret = real_{name}({params_call});")
            result.append("    if (ret == 0 && fd >= 0 && fd < MAX_SOCKETS) {")
            result.append("        std::lock_guard<std::mutex> lock(m_socketMutex);")
            result.append("        m_socketInfo[fd] = {}; // Reset the socket info")
            result.append("        debug(\"close(%d) = %d\\n\", fd, ret);")
            result.append("    }")
            result.append("    return ret;")
        else:
            result.append(f"    return real_{name}({params_call});")
        result.append("}")

    return "\n".join(result)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <network_functions.json> <output_mode>")
        print("Output modes: header, implementation, all")
        sys.exit(1)

    json_file = sys.argv[1]
    output_mode = sys.argv[2]

    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error reading JSON file: {e}")
        sys.exit(1)

    functions = data.get("network_functions", [])

    if not functions:
        print("No network functions found in the JSON file")
        sys.exit(1)

    # Generate C++ code based on output mode
    if output_mode == "header":
        # For header file
        function_pointer_types = generate_function_pointer_types(functions)
        function_pointer_declarations = generate_function_pointer_declarations(functions)
        interceptor_method_declarations = generate_interceptor_methods_declarations(functions)

        print(f"// Generated code from {os.path.basename(json_file)}")
        print("")
        print("// Function pointer typedefs")
        print(function_pointer_types)
        print("")
        print("// Function pointer declarations (static members)")
        print(function_pointer_declarations)
        print("")
        print("// Function loading prototype")
        print("void loadOriginalFunctions();")
        print("")
        print("// NetworkInterceptor method declarations")
        print(interceptor_method_declarations)

    elif output_mode == "implementation":
        # For implementation file
        function_pointer_definitions = generate_function_pointer_definitions(functions)
        function_loading = generate_function_loading(functions)
        function_interceptors = generate_function_interceptors(functions)
        interceptor_methods = generate_interceptor_methods(functions)

        print(f"// Generated code from {os.path.basename(json_file)}")
        print("")
        print('#include "generated_bindings_header.hpp"')
        print("")
        print("// Function pointer definitions (static members)")
        print(function_pointer_definitions)
        print("")
        print("// Function loading implementation")
        print("void loadOriginalFunctions() {")
        print(function_loading)
        print("}")
        print("")
        print("// NetworkInterceptor method implementations")
        print(interceptor_methods)
        print("")
        print("// Function interceptors")
        print(function_interceptors)

    elif output_mode == "all":
        # All in one file
        function_pointer_types = generate_function_pointer_types(functions)
        function_pointer_declarations = generate_function_pointer_declarations(functions)
        function_pointer_definitions = generate_function_pointer_definitions(functions)
        function_loading = generate_function_loading(functions)
        interceptor_method_declarations = generate_interceptor_methods_declarations(functions)
        interceptor_methods = generate_interceptor_methods(functions)
        function_interceptors = generate_function_interceptors(functions)

        print(f"// Generated code from {os.path.basename(json_file)}")
        print("")
        print("// Function pointer typedefs")
        print(function_pointer_types)
        print("")
        print("// Function pointer declarations (static members)")
        print(function_pointer_declarations)
        print("")
        print("// Function pointer definitions (static members)")
        print(function_pointer_definitions)
        print("")
        print("// Function loading code")
        print("void loadOriginalFunctions() {")
        print(function_loading)
        print("}")
        print("")
        print("// NetworkInterceptor method declarations")
        print(interceptor_method_declarations)
        print("")
        print("// NetworkInterceptor method implementations")
        print(interceptor_methods)
        print("")
        print("// Function interceptors")
        print(function_interceptors)
    else:
        print(f"Error: Unknown output mode '{output_mode}'")
        print("Valid modes: header, implementation, all")
        sys.exit(1)

if __name__ == "__main__":
    main()
