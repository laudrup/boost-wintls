//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

#ifndef WINTLS_TEST_TEST_STREAM_IMPL_STREAM_IPP
#define WINTLS_TEST_TEST_STREAM_IMPL_STREAM_IPP

#include <memory>
#include <stdexcept>
#include <vector>

namespace wintls {
namespace test {

//------------------------------------------------------------------------------

stream::
service::
service(net::execution_context& ctx)
    : service_base<service>(ctx)
    , sp_(std::make_shared<service_impl>())
{
}

void
stream::
service::
shutdown()
{
    std::vector<std::unique_ptr<read_op_base>> v;
    std::lock_guard<std::mutex> g1(sp_->m_);
    v.reserve(sp_->v_.size());
    for(auto p : sp_->v_)
    {
        std::lock_guard<std::mutex> g2(p->m);
        v.emplace_back(std::move(p->op));
        p->code = status::eof;
    }
}

auto
stream::
service::
make_impl(
    net::io_context& ctx,
    test::fail_count* fc) ->
    std::shared_ptr<state>
{
    auto& svc = net::use_service<service>(ctx);
    auto sp = std::make_shared<state>(ctx, svc.sp_, fc);
    std::lock_guard<std::mutex> g(svc.sp_->m_);
    svc.sp_->v_.push_back(sp.get());
    return sp;
}

void
stream::
service_impl::
remove(state& impl)
{
    std::lock_guard<std::mutex> g(m_);
    *std::find(
        v_.begin(), v_.end(),
            &impl) = std::move(v_.back());
    v_.pop_back();
}

//------------------------------------------------------------------------------

void stream::initiate_read(
    std::shared_ptr<state> const& in_,
    std::unique_ptr<stream::read_op_base>&& op,
    std::size_t buf_size)
{
    std::unique_lock<std::mutex> lock(in_->m);

    ++in_->nread;
    if(in_->op != nullptr)
        throw std::logic_error{"in_->op != nullptr"};

    // test failure
    error_code ec;
    if(in_->fc && in_->fc->fail(ec))
    {
        lock.unlock();
        (*op)(ec);
        return;
    }

    // A request to read 0 bytes from a stream is a no-op.
    if(buf_size == 0 || in_->b.data().size() > 0)
    {
        lock.unlock();
        (*op)(ec);
        return;
    }

    // deliver error
    if(in_->code != status::ok)
    {
        lock.unlock();
        (*op)(net::error::eof);
        return;
    }

    // complete when bytes available or closed
    in_->op = std::move(op);
}

stream::
state::
state(
    net::io_context& ioc_,
    std::weak_ptr<service_impl> wp_,
    fail_count* fc_)
    : ioc(ioc_)
    , wp(std::move(wp_))
    , fc(fc_)
{
}

stream::
state::
~state()
{
    // cancel outstanding read
    if(op != nullptr)
        (*op)(net::error::operation_aborted);
}

void
stream::
state::
remove() noexcept
{
    auto sp = wp.lock();

    // If this goes off, it means the lifetime of a test::stream object
    // extended beyond the lifetime of the associated execution context.
    assert(sp);

    sp->remove(*this);
}

void
stream::
state::
notify_read()
{
    if(op)
    {
        auto op_ = std::move(op);
        op_->operator()(error_code{});
    }
    else
    {
        cv.notify_all();
    }
}

void
stream::
state::
cancel_read()
{
    std::unique_ptr<read_op_base> p;
    {
        std::lock_guard<std::mutex> lock(m);
        code = status::eof;
        p = std::move(op);
    }
    if(p != nullptr)
        (*p)(net::error::operation_aborted);
}

//------------------------------------------------------------------------------

stream::
~stream()
{
    close();
    in_->remove();
}

stream::
stream(stream&& other)
{
    auto in = service::make_impl(
        other.in_->ioc, other.in_->fc);
    in_ = std::move(other.in_);
    out_ = std::move(other.out_);
    other.in_ = in;
}

stream&
stream::
operator=(stream&& other)
{
    close();
    auto in = service::make_impl(
        other.in_->ioc, other.in_->fc);
    in_->remove();
    in_ = std::move(other.in_);
    out_ = std::move(other.out_);
    other.in_ = in;
    return *this;
}

//------------------------------------------------------------------------------

stream::
stream(net::io_context& ioc)
    : in_(service::make_impl(ioc, nullptr))
{
}

stream::
stream(
    net::io_context& ioc,
    fail_count& fc)
    : in_(service::make_impl(ioc, &fc))
{
}

stream::
stream(
    net::io_context& ioc,
    string_view s)
    : in_(service::make_impl(ioc, nullptr))
{
    in_->b.commit(net::buffer_copy(
        in_->b.prepare(s.size()),
        net::buffer(s.data(), s.size())));
}

stream::
stream(
    net::io_context& ioc,
    fail_count& fc,
    string_view s)
    : in_(service::make_impl(ioc, &fc))
{
    in_->b.commit(net::buffer_copy(
        in_->b.prepare(s.size()),
        net::buffer(s.data(), s.size())));
}

void
stream::
connect(stream& remote)
{
    assert(! out_.lock());
    assert(! remote.out_.lock());
    std::lock(in_->m, remote.in_->m);
    std::lock_guard<std::mutex> guard1{in_->m, std::adopt_lock};
    std::lock_guard<std::mutex> guard2{remote.in_->m, std::adopt_lock};
    out_ = remote.in_;
    remote.out_ = in_;
    in_->code = status::ok;
    remote.in_->code = status::ok;
}

string_view
stream::
str() const
{
    auto const bs = in_->b.data();
    if(bs.size() == 0)
        return {};
    net::const_buffer const b = *net::buffer_sequence_begin(bs);
    return {static_cast<char const*>(b.data()), b.size()};
}

void
stream::
append(string_view s)
{
    std::lock_guard<std::mutex> lock{in_->m};
    in_->b.commit(net::buffer_copy(
        in_->b.prepare(s.size()),
        net::buffer(s.data(), s.size())));
}

void
stream::
clear()
{
    std::lock_guard<std::mutex> lock{in_->m};
    in_->b.consume(in_->b.size());
}

void
stream::
close()
{
    in_->cancel_read();

    // disconnect
    {
        auto out = out_.lock();
        out_.reset();

        // notify peer
        if(out)
        {
            std::lock_guard<std::mutex> lock(out->m);
            if(out->code == status::ok)
            {
                out->code = status::eof;
                out->notify_read();
            }
        }
    }
}

void
stream::
close_remote()
{
    std::lock_guard<std::mutex> lock{in_->m};
    if(in_->code == status::ok)
    {
        in_->code = status::eof;
        in_->notify_read();
    }
}

void
teardown(
    role_type,
    stream& s,
    error_code& ec)
{
    if( s.in_->fc &&
        s.in_->fc->fail(ec))
        return;

    s.close();

    if( s.in_->fc &&
        s.in_->fc->fail(ec))
        ec = net::error::eof;
    else
        ec = {};
}

//------------------------------------------------------------------------------

stream
connect(stream& to)
{
    stream from{to.get_executor().context()};
    from.connect(to);
    return from;
}

void
connect(stream& s1, stream& s2)
{
    s1.connect(s2);
}

} // namespace test
} // namespace wintls

#endif // WINTLS_TEST_TEST_STREAM_IMPL_STREAM_IPP
