#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include <nan.h>
#include "../argon2/include/argon2.h"

#include <v8.h>
using namespace std;
using namespace v8;


#ifndef _MSC_VER
namespace {
#endif

class Options {
public:
    // TODO: remove ctors and initializers when GCC<5 stops shipping on Ubuntu
    Options() = default;
    Options(Options&&) = default;

    v8::Local<v8::Object> dump(const std::string& hash) const
    {
        auto out = Nan::New<v8::Object>();
        Nan::Set(out, Nan::New("id").ToLocalChecked(), Nan::New(argon2_type2string(type, false)).ToLocalChecked());
        Nan::Set(out, Nan::New("version").ToLocalChecked(), Nan::New(version));

        auto params = Nan::New<v8::Object>();
        Nan::Set(params, Nan::New("m").ToLocalChecked(), Nan::New(memory_cost));
        Nan::Set(params, Nan::New("t").ToLocalChecked(), Nan::New(time_cost));
        Nan::Set(params, Nan::New("p").ToLocalChecked(), Nan::New(parallelism));
        Nan::Set(out, Nan::New("params").ToLocalChecked(), params);

        Nan::Set(out, Nan::New("salt").ToLocalChecked(), Nan::CopyBuffer(salt.c_str(), salt.size()).ToLocalChecked());
        Nan::Set(out, Nan::New("hash").ToLocalChecked(), Nan::CopyBuffer(hash.c_str(), hash.size()).ToLocalChecked());
        return out;
    }

    v8::Local<v8::Object> simple(const std::string& hash) const
    {
        auto out = Nan::New<v8::Object>();
        Nan::Set(out, Nan::New("hash").ToLocalChecked(), Nan::CopyBuffer(hash.c_str(), hash.size()).ToLocalChecked());
        return out;
    }

    std::string salt;

    uint32_t hash_length = {};
    uint32_t time_cost = {};
    uint32_t memory_cost = {};
    uint32_t parallelism = {};
    uint32_t version = {};

    argon2_type type = {};
};

argon2_context make_context(char* buf, const std::string& plain, const Options& options) {
    argon2_context ctx;

    ctx.out = reinterpret_cast<uint8_t*>(buf);
    ctx.outlen = options.hash_length;
    ctx.pwd = reinterpret_cast<uint8_t*>(const_cast<char*>(plain.data()));
    ctx.pwdlen = plain.size();
    ctx.salt = reinterpret_cast<uint8_t*>(const_cast<char*>(options.salt.data()));
    ctx.saltlen = options.salt.size();
    ctx.secret = nullptr;
    ctx.secretlen = 0;
    ctx.ad = nullptr;
    ctx.adlen = 0;
    ctx.t_cost = options.time_cost;
    ctx.m_cost = options.memory_cost;
    ctx.lanes = options.parallelism;
    ctx.threads = options.parallelism;
    ctx.allocate_cbk = nullptr;
    ctx.free_cbk = nullptr;
    ctx.flags = ARGON2_DEFAULT_FLAGS;
    ctx.version = options.version;

    return ctx;
}

class HashWorker final: public Nan::AsyncWorker {
public:
    HashWorker(Nan::Callback* callback, std::string plain, Options options) :
        Nan::AsyncWorker{callback, "argon2:HashWorker"},
        plain{std::move(plain)},
        options{std::move(options)}
    {}

    void Execute() override
    {
#ifdef _MSC_VER
        char* buf = new char[32];
#else
        char buf[32];
#endif
        genHash(buf);
        std::fill_n(buf, 32, 0);
#ifdef _MSC_VER
        delete[] buf;
#endif
    }

    void genHash(char * buf )
    {
        auto ctx = make_context(buf, plain, options);
        int result = argon2_ctx(&ctx, options.type);

        if (result != ARGON2_OK) {
            // LCOV_EXCL_START
            SetErrorMessage(argon2_error_message(result));
            // LCOV_EXCL_STOP
        } else {
            hash.assign(buf, options.hash_length);
        }
    }

    void HandleOKCallback() override
    {
        Nan::HandleScope scope;

        v8::Local<v8::Value> argv[] = {
            Nan::Null(),
            options.dump(hash),
        };

        callback->Call(2, argv, async_resource);
    }

private:
    std::string plain;
    Options options;

    std::string hash;
};


class BatchWorker final: public Nan::AsyncWorker {
public:
    BatchWorker(Nan::Callback* callback, vector<string> buffers, Options options) :
        Nan::AsyncWorker{callback, "argon2:BatchWorker"},
        buffers{std::move(buffers)},
        options{std::move(options)}
    {}

    void Execute() override
    {
#ifdef _MSC_VER
        char* buf = new char[32];
#else
        char buf[32];
#endif
        std::string hash;

        for (string& val : buffers) {

            auto ctx = make_context(buf, val, options);
            int result = argon2_ctx(&ctx, options.type);

            if (result != ARGON2_OK) {
                // LCOV_EXCL_START
                SetErrorMessage(argon2_error_message(result));
                // LCOV_EXCL_STOP
            } else {
                // copy hash_length bytes from buf to hash var
                hash.assign(buf, options.hash_length);
            }

            // save hash to results
            results.push_back( hash );

            // reset buffer
            std::fill_n(buf, 32, 0);
        }

#ifdef _MSC_VER
        delete[] buf;
#endif
    }

    void HandleOKCallback() override
    {
        Nan::HandleScope scope;

        // Convert string Vector to V8 array
        Handle<Array> resultArray = Nan::New<v8::Array>( results.size() );
        for (unsigned i=0; i < results.size(); i++) {

            // v8::Local<v8::Value> thisval = Nan::New(results[i]).ToLocalChecked();
            v8::Local<v8::Value> thisval = Nan::CopyBuffer(results[i].c_str(), results[i].size()).ToLocalChecked();

            Nan::Set( resultArray, i, thisval );
        }

        v8::Local<v8::Value> argv[] = {
            Nan::Null(),
            resultArray,
        };

        callback->Call(2, argv, async_resource);
    }


private:

    vector<string> buffers;
    vector<string> results;
    Options options;
};

using size_type = std::string::size_type;

v8::Local<v8::Value> from_object(const v8::Local<v8::Object>& object, const char* key)
{
    return Nan::Get(object, Nan::New(key).ToLocalChecked()).ToLocalChecked();
}

template<class ReturnValue, class T>
ReturnValue to_just(const T& object)
{
    return Nan::To<ReturnValue>(object).FromJust();
}

template<class T>
std::string to_string(const T& object)
{
    auto&& conv = Nan::To<v8::Object>(object).ToLocalChecked();
    return {node::Buffer::Data(conv), node::Buffer::Length(conv)};
}

Options extract_options(const v8::Local<v8::Object>& options)
{
    Options ret;
    ret.salt = to_string(from_object(options, "salt"));
    ret.hash_length = to_just<uint32_t>(from_object(options, "hashLength"));
    ret.time_cost = to_just<uint32_t>(from_object(options, "timeCost"));
    ret.memory_cost = to_just<uint32_t>(from_object(options, "memoryCost"));
    ret.parallelism = to_just<uint32_t>(from_object(options, "parallelism"));
    ret.version = to_just<uint32_t>(from_object(options, "version"));
    ret.type = argon2_type(to_just<uint32_t>(from_object(options, "type")));
    return ret;
}

#ifndef _MSC_VER
}
#endif

NAN_METHOD(Hash) {
    assert(info.Length() == 3);

    auto&& plain = to_string(info[0]);
    auto&& options = Nan::To<v8::Object>(info[1]).ToLocalChecked();
    auto callback = new Nan::Callback{
        Nan::To<v8::Function>(info[2]).ToLocalChecked()
    };

    auto worker = new HashWorker{
        callback, std::move(plain), extract_options(options),
    };

    Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(Batch) {
    assert(info.Length() == 3);

    if (!info[0]->IsArray()) {
        return Nan::ThrowError(Nan::New(
          "aMethodName - expected arg 0 to be of type: ARRAY"
        ).ToLocalChecked());
    }


    vector<string> buffers;
    Handle<Array> jsArray = Handle<Array>::Cast(info[0]);

    for (unsigned int i = 0; i < jsArray->Length(); i++) {
        buffers.push_back( to_string( jsArray->Get(i) ) );
    }


    auto&& options = Nan::To<v8::Object>(info[1]).ToLocalChecked();

    auto callback = new Nan::Callback{
        Nan::To<v8::Function>(info[2]).ToLocalChecked()
    };

    auto worker = new BatchWorker{
        callback, buffers, extract_options(options),
    };

    Nan::AsyncQueueWorker(worker);
}

NAN_MODULE_INIT(init) {
    auto limits = Nan::New<v8::Object>();

    const auto setMaxMin = [&](const char* name, uint32_t max, uint32_t min) {
        auto obj = Nan::New<v8::Object>();
        Nan::Set(obj, Nan::New("max").ToLocalChecked(), Nan::New<v8::Number>(max));
        Nan::Set(obj, Nan::New("min").ToLocalChecked(), Nan::New<v8::Number>(min));
        Nan::Set(limits, Nan::New(name).ToLocalChecked(), obj);
    };

    setMaxMin("hashLength", ARGON2_MAX_OUTLEN, ARGON2_MIN_OUTLEN);
    setMaxMin("memoryCost", ARGON2_MAX_MEMORY, ARGON2_MIN_MEMORY);
    setMaxMin("timeCost", ARGON2_MAX_TIME, ARGON2_MIN_TIME);
    setMaxMin("parallelism", ARGON2_MAX_LANES, ARGON2_MIN_LANES);

    auto types = Nan::New<v8::Object>();

    const auto setType = [&](argon2_type type) {
        Nan::Set(types,
                Nan::New(argon2_type2string(type, false)).ToLocalChecked(),
                Nan::New<v8::Number>(type));
    };

    setType(Argon2_d);
    setType(Argon2_i);
    setType(Argon2_id);

    Nan::Set(target, Nan::New("limits").ToLocalChecked(), limits);
    Nan::Set(target, Nan::New("types").ToLocalChecked(), types);
    Nan::Set(target, Nan::New("version").ToLocalChecked(),
            Nan::New<v8::Number>(ARGON2_VERSION_NUMBER));

    Nan::Export(target, "batch", Batch);
    Nan::Export(target, "hash", Hash);
}


NODE_MODULE(argon2_lib, init);
