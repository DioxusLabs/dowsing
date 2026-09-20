//! The network model: the target's sockets, epoll instances and eventfds exist only here.
//!
//! Descriptors handed to the target are numbered from [`VFD_BASE`] so the seccomp filter can
//! tell them from real kernel fds by the first syscall argument alone; everything the target
//! does with one is emulated in [`syscalls`], and nothing about them lives in the kernel, which
//! is what keeps a snapshot restorable. The peers are modelled clients: each opens one
//! connection to the target's listener, sends one request (chosen from the corpus), possibly in
//! pieces, and closes. *When* any of that happens is a schedule decision, offered next to the
//! target's own threads. What a complete request or response looks like, and which responses
//! are failures, is the [`Protocol`]'s business ([`http1::Http1`] by default).

mod http1;
mod syscalls;

pub use crate::model::VFD_BASE;
pub use http1::Http1;

use crate::world::Outcome;
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::Arc,
};

/// Framing and verdicts of the bytes a client exchanges with the target.
pub trait Protocol: fmt::Debug + Send + Sync {
    /// `req` is a complete request: a server holding the connection without answering has hung.
    fn request_complete(&self, req: &[u8]) -> bool;
    /// `resp` is a complete response.
    fn response_complete(&self, resp: &[u8]) -> bool;
    /// A failure the response itself reveals, checked on every write.
    fn verdict(&self, resp: &[u8]) -> Option<Outcome>;
}

/// Address a modelled client connects from: `127.0.0.1:CLIENT_PORT_BASE + id`.
pub const CLIENT_PORT_BASE: u16 = 50000;
/// Address a listener bound to port 0 gets.
const EPHEMERAL_PORT_BASE: u16 = 40000;

pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;

pub type ObjId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interest {
    pub events: u32,
    pub data: u64,
    /// Edge-triggered: readiness transitions not yet reported.
    pub armed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SockState {
    Fresh,
    Listening {
        backlog: VecDeque<usize>,
    },
    /// Accepted server side of client `client`'s connection.
    Connected {
        client: usize,
        shut_wr: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Obj {
    Epoll {
        interests: BTreeMap<i32, Interest>,
    },
    EventFd {
        count: u64,
        nonblock: bool,
    },
    Socket {
        nonblock: bool,
        local: Option<(u32, u16)>,
        state: SockState,
    },
}

/// One modelled client and its connection to the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub request: Vec<u8>,
    /// Bytes of `request` handed to the connection so far.
    pub sent: usize,
    /// Delivered but not yet read by the target.
    pub rx: Vec<u8>,
    /// Client closed its sending side.
    pub fin: bool,
    pub accepted: bool,
    pub response: Vec<u8>,
    /// Target closed or shut down its side.
    pub server_closed: bool,
}

impl Client {
    pub fn new(request: Vec<u8>) -> Self {
        Self {
            request,
            sent: 0,
            rx: Vec::new(),
            fin: false,
            accepted: false,
            response: Vec::new(),
            server_closed: false,
        }
    }

    pub fn remaining(&self) -> usize {
        self.request.len() - self.sent
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientEvent {
    /// A new client connects to the (first) listening socket.
    Connect,
    /// Client `0` delivers the next piece of its request.
    Send(usize),
    /// Client `0` closes its sending side.
    Close(usize),
}

/// What a client sends when the run has no corpus.
const DEFAULT_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

#[derive(Debug, Clone)]
pub struct Net {
    pub fds: BTreeMap<i32, ObjId>,
    pub objs: BTreeMap<ObjId, (Obj, u32)>,
    next_obj: ObjId,
    next_port: u16,
    pub clients: Vec<Client>,
    /// Connections the run may open.
    pub max_clients: usize,
    /// Requests a client may send (a `Payload` decision picks one).
    pub requests: Arc<Vec<Vec<u8>>>,
    pub protocol: Arc<dyn Protocol>,
}

impl Default for Net {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Net {
    /// HTTP/1 peers sending the default request.
    pub fn new(max_clients: usize) -> Self {
        Self::with(max_clients, Vec::new(), Arc::new(Http1))
    }

    /// `max_clients` peers of `protocol`, each sending one request from `requests` (empty = a
    /// default GET).
    pub fn with(max_clients: usize, requests: Vec<Vec<u8>>, protocol: Arc<dyn Protocol>) -> Self {
        let requests = if requests.is_empty() {
            vec![DEFAULT_REQUEST.to_vec()]
        } else {
            requests
        };
        Self {
            fds: BTreeMap::new(),
            objs: BTreeMap::new(),
            next_obj: 0,
            next_port: 0,
            clients: Vec::new(),
            max_clients,
            requests: Arc::new(requests),
            protocol,
        }
    }

    pub fn is_virtual(fd: i32) -> bool {
        fd >= VFD_BASE
    }

    fn alloc_fd(&mut self, min: i32) -> i32 {
        let mut fd = min.max(VFD_BASE);
        while self.fds.contains_key(&fd) {
            fd += 1;
        }
        fd
    }

    /// Create an object and one descriptor for it (at or above `min`).
    pub fn create(&mut self, obj: Obj, min: i32) -> i32 {
        let id = self.next_obj;
        self.next_obj += 1;
        self.objs.insert(id, (obj, 1));
        let fd = self.alloc_fd(min);
        self.fds.insert(fd, id);
        fd
    }

    pub fn dup(&mut self, fd: i32, min: i32) -> Option<i32> {
        let id = *self.fds.get(&fd)?;
        let new = self.alloc_fd(min);
        self.fds.insert(new, id);
        self.objs.get_mut(&id).expect("dangling fd").1 += 1;
        Some(new)
    }

    pub fn obj_of(&self, fd: i32) -> Option<ObjId> {
        self.fds.get(&fd).copied()
    }

    pub fn get(&self, fd: i32) -> Option<&Obj> {
        self.objs.get(self.fds.get(&fd)?).map(|(o, _)| o)
    }

    pub fn get_mut(&mut self, fd: i32) -> Option<&mut Obj> {
        let id = *self.fds.get(&fd)?;
        self.objs.get_mut(&id).map(|(o, _)| o)
    }

    /// Close one descriptor; when the last one goes the object is dropped. `None` for an
    /// unknown descriptor (EBADF); otherwise the affected client if a connection was closed.
    pub fn close(&mut self, fd: i32) -> Option<Option<usize>> {
        let id = self.fds.remove(&fd)?;
        for (o, _) in self.objs.values_mut() {
            if let Obj::Epoll { interests } = o {
                interests.remove(&fd);
            }
        }
        let (_, refs) = self.objs.get_mut(&id).expect("dangling fd");
        *refs -= 1;
        if *refs > 0 {
            return Some(None);
        }
        let (obj, _) = self.objs.remove(&id).expect("object");
        Some(match obj {
            Obj::Socket {
                state: SockState::Connected { client, .. },
                ..
            } => {
                self.clients[client].server_closed = true;
                Some(client)
            }
            _ => None,
        })
    }

    pub fn nonblock(&self, fd: i32) -> bool {
        match self.get(fd) {
            Some(Obj::EventFd { nonblock, .. }) | Some(Obj::Socket { nonblock, .. }) => *nonblock,
            _ => true,
        }
    }

    pub fn set_nonblock(&mut self, fd: i32, on: bool) {
        match self.get_mut(fd) {
            Some(Obj::EventFd { nonblock, .. }) | Some(Obj::Socket { nonblock, .. }) => {
                *nonblock = on
            }
            _ => {}
        }
    }

    pub fn bind(&mut self, fd: i32, addr: u32, port: u16) -> i64 {
        let Some(Obj::Socket { local, .. }) = self.get_mut(fd) else {
            return -(libc::ENOTSOCK as i64);
        };
        if local.is_some() {
            return -(libc::EINVAL as i64);
        }
        let port = if port == 0 {
            let p = EPHEMERAL_PORT_BASE + self.next_port;
            self.next_port += 1;
            p
        } else {
            port
        };
        match self.get_mut(fd) {
            Some(Obj::Socket { local, .. }) => *local = Some((addr, port)),
            _ => unreachable!(),
        }
        0
    }

    pub fn listen(&mut self, fd: i32) -> i64 {
        match self.get_mut(fd) {
            Some(Obj::Socket { state, local, .. }) => {
                if local.is_none() {
                    *local = Some((0x7f00_0001, EPHEMERAL_PORT_BASE));
                }
                if matches!(state, SockState::Fresh) {
                    *state = SockState::Listening {
                        backlog: VecDeque::new(),
                    };
                }
                0
            }
            Some(_) => -(libc::ENOTSOCK as i64),
            None => -(libc::EBADF as i64),
        }
    }

    pub fn listener(&self) -> Option<ObjId> {
        self.objs.iter().find_map(|(id, (o, _))| match o {
            Obj::Socket {
                state: SockState::Listening { .. },
                ..
            } => Some(*id),
            _ => None,
        })
    }

    /// Descriptors referring to `obj`.
    pub fn fds_of(&self, obj: ObjId) -> Vec<i32> {
        self.fds
            .iter()
            .filter(|(_, id)| **id == obj)
            .map(|(fd, _)| *fd)
            .collect()
    }

    pub fn socket_of_client(&self, client: usize) -> Option<ObjId> {
        self.objs.iter().find_map(|(id, (o, _))| match o {
            Obj::Socket {
                state: SockState::Connected { client: c, .. },
                ..
            } if *c == client => Some(*id),
            _ => None,
        })
    }

    /// Current readiness of `fd` as epoll would report it.
    pub fn ready(&self, fd: i32) -> u32 {
        match self.get(fd) {
            Some(Obj::EventFd { count, .. }) => EPOLLOUT | if *count > 0 { EPOLLIN } else { 0 },
            Some(Obj::Socket { state, .. }) => match state {
                SockState::Fresh => EPOLLOUT | EPOLLHUP,
                SockState::Listening { backlog } => {
                    if backlog.is_empty() {
                        0
                    } else {
                        EPOLLIN
                    }
                }
                SockState::Connected { client, shut_wr } => {
                    let c = &self.clients[*client];
                    let mut r = 0;
                    if !c.rx.is_empty() || c.fin {
                        r |= EPOLLIN;
                    }
                    if c.fin {
                        r |= EPOLLRDHUP;
                        if *shut_wr {
                            r |= EPOLLHUP;
                        }
                    }
                    if !*shut_wr {
                        r |= EPOLLOUT;
                    }
                    r
                }
            },
            Some(Obj::Epoll { .. }) | None => 0,
        }
    }

    /// Readiness of `fd` changed by `mask`: arm the edge-triggered interests in it.
    pub fn signal(&mut self, obj: ObjId, mask: u32) {
        let fds = self.fds_of(obj);
        for (o, _) in self.objs.values_mut() {
            if let Obj::Epoll { interests } = o {
                for fd in &fds {
                    if let Some(i) = interests.get_mut(fd) {
                        i.armed |= mask & (i.events | EPOLLERR | EPOLLHUP);
                    }
                }
            }
        }
    }

    pub fn epoll_ctl(&mut self, epfd: i32, op: i32, fd: i32, events: u32, data: u64) -> i64 {
        if !self.fds.contains_key(&fd) {
            return -(libc::EBADF as i64);
        }
        let ready = self.ready(fd);
        let Some(Obj::Epoll { interests }) = self.get_mut(epfd) else {
            return -(libc::EINVAL as i64);
        };
        match op {
            libc::EPOLL_CTL_ADD => {
                if interests.contains_key(&fd) {
                    return -(libc::EEXIST as i64);
                }
                interests.insert(
                    fd,
                    Interest {
                        events,
                        data,
                        armed: ready & (events | EPOLLERR | EPOLLHUP),
                    },
                );
                0
            }
            libc::EPOLL_CTL_MOD => match interests.get_mut(&fd) {
                Some(i) => {
                    i.events = events;
                    i.data = data;
                    i.armed = ready & (events | EPOLLERR | EPOLLHUP);
                    0
                }
                None => -(libc::ENOENT as i64),
            },
            libc::EPOLL_CTL_DEL => {
                if interests.remove(&fd).is_none() {
                    return -(libc::ENOENT as i64);
                }
                0
            }
            _ => -(libc::EINVAL as i64),
        }
    }

    /// Events `epoll_wait` on `epfd` would return now (at most `max`), consuming edges.
    pub fn epoll_poll(&mut self, epfd: i32, max: usize) -> Vec<(u32, u64)> {
        let Some(Obj::Epoll { interests }) = self.get(epfd) else {
            return Vec::new();
        };
        let fds: Vec<i32> = interests.keys().copied().collect();
        let mut out = Vec::new();
        for fd in fds {
            if out.len() >= max {
                break;
            }
            let ready = self.ready(fd);
            let Some(Obj::Epoll { interests }) = self.get_mut(epfd) else {
                unreachable!()
            };
            let Some(i) = interests.get_mut(&fd) else {
                continue;
            };
            let live = ready & (i.events | EPOLLERR | EPOLLHUP);
            let report = if i.events & EPOLLET != 0 {
                i.armed & live
            } else {
                live
            };
            if report == 0 {
                i.armed = 0;
                continue;
            }
            i.armed = 0;
            if i.events & EPOLLONESHOT != 0 {
                i.events &= !(EPOLLIN | EPOLLOUT | EPOLLRDHUP);
            }
            out.push((report, i.data));
        }
        out
    }

    // ------------------------------------------------------------------------------------
    // Modelled clients
    // ------------------------------------------------------------------------------------

    /// Client events that could happen now. A client sends its whole request before it may
    /// close: a half-sent request is a fault the corpus can express directly, not a schedule.
    pub fn client_events(&self) -> Vec<ClientEvent> {
        let mut ev = Vec::new();
        if self.clients.len() < self.max_clients && self.listener().is_some() {
            ev.push(ClientEvent::Connect);
        }
        for (i, c) in self.clients.iter().enumerate() {
            if c.fin || c.server_closed {
                continue;
            }
            if c.remaining() > 0 {
                ev.push(ClientEvent::Send(i));
            } else {
                ev.push(ClientEvent::Close(i));
            }
        }
        ev
    }

    /// A client whose complete request the target has read is still waiting for an answer.
    pub fn hung_clients(&self) -> Vec<usize> {
        self.clients
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                c.accepted
                    && !c.server_closed
                    && c.remaining() == 0
                    && c.rx.is_empty()
                    && self.protocol.request_complete(&c.request)
                    && !self.protocol.response_complete(&c.response)
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Queue a new connection on the listener. Returns the client index and listener object.
    pub fn connect(&mut self, request: Vec<u8>) -> Option<(usize, ObjId)> {
        let listener = self.listener()?;
        let id = self.clients.len();
        self.clients.push(Client::new(request));
        if let Some((
            Obj::Socket {
                state: SockState::Listening { backlog },
                ..
            },
            _,
        )) = self.objs.get_mut(&listener)
        {
            backlog.push_back(id);
        }
        Some((id, listener))
    }

    /// Deliver `n` more bytes of client `c`'s request.
    pub fn deliver(&mut self, c: usize, n: usize) {
        let client = &mut self.clients[c];
        let n = n.min(client.remaining());
        let bytes = client.request[client.sent..client.sent + n].to_vec();
        client.sent += n;
        client.rx.extend_from_slice(&bytes);
    }

    /// Accept on `fd`: the server side socket for the oldest queued client, or `None`.
    pub fn accept(&mut self, fd: i32, nonblock: bool) -> Option<(i32, usize)> {
        let local = match self.get(fd) {
            Some(Obj::Socket { local, .. }) => *local,
            _ => None,
        };
        let Some(Obj::Socket {
            state: SockState::Listening { backlog },
            ..
        }) = self.get_mut(fd)
        else {
            return None;
        };
        let client = backlog.pop_front()?;
        self.clients[client].accepted = true;
        let new = self.create(
            Obj::Socket {
                nonblock,
                local,
                state: SockState::Connected {
                    client,
                    shut_wr: false,
                },
            },
            VFD_BASE,
        );
        Some((new, client))
    }
}

/// HTTP/1.x request completeness (see [`Http1`]).
pub fn http_request_complete(req: &[u8]) -> bool {
    Http1.request_complete(req)
}

/// HTTP/1.x response completeness (see [`Http1`]).
pub fn http_response_complete(resp: &[u8]) -> bool {
    Http1.response_complete(resp)
}

/// Status code of the first response line in `bytes`, if one starts there.
pub fn http_status(bytes: &[u8]) -> Option<u16> {
    http1::status(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(net: &mut Net) -> i32 {
        let fd = net.create(
            Obj::Socket {
                nonblock: true,
                local: None,
                state: SockState::Fresh,
            },
            VFD_BASE,
        );
        assert_eq!(net.bind(fd, 0x7f00_0001, 8080), 0);
        assert_eq!(net.listen(fd), 0);
        fd
    }

    #[test]
    fn edge_triggered_events_fire_once_per_transition() {
        let mut net = Net::new(2);
        let l = listener(&mut net);
        let ep = net.create(
            Obj::Epoll {
                interests: BTreeMap::new(),
            },
            VFD_BASE,
        );
        assert_eq!(
            net.epoll_ctl(ep, libc::EPOLL_CTL_ADD, l, EPOLLIN | EPOLLET, 7),
            0
        );
        assert!(net.epoll_poll(ep, 16).is_empty());
        let (c, lobj) = net.connect(b"GET / HTTP/1.1\r\n\r\n".to_vec()).unwrap();
        net.signal(lobj, EPOLLIN);
        assert_eq!(net.epoll_poll(ep, 16), vec![(EPOLLIN, 7)]);
        assert!(net.epoll_poll(ep, 16).is_empty(), "edge consumed");
        let (s, client) = net.accept(l, true).unwrap();
        assert_eq!(client, c);
        assert!(net.accept(l, true).is_none());
        assert_eq!(
            net.epoll_ctl(
                ep,
                libc::EPOLL_CTL_ADD,
                s,
                EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET,
                9
            ),
            0
        );
        assert_eq!(
            net.epoll_poll(ep, 16),
            vec![(EPOLLOUT, 9)],
            "writable at add"
        );
        net.deliver(c, 5);
        let sobj = net.socket_of_client(c).unwrap();
        net.signal(sobj, EPOLLIN);
        assert_eq!(net.epoll_poll(ep, 16), vec![(EPOLLIN, 9)]);
        net.clients[c].fin = true;
        net.signal(sobj, EPOLLIN | EPOLLRDHUP);
        assert_eq!(net.epoll_poll(ep, 16), vec![(EPOLLIN | EPOLLRDHUP, 9)]);
        assert_eq!(net.close(s), Some(Some(c)));
        assert!(net.clients[c].server_closed);
        assert!(
            matches!(net.get(ep), Some(Obj::Epoll { interests }) if !interests.contains_key(&s))
        );
    }

    #[test]
    fn dup_shares_the_object_until_the_last_close() {
        let mut net = Net::new(0);
        let ep = net.create(
            Obj::Epoll {
                interests: BTreeMap::new(),
            },
            VFD_BASE,
        );
        let ep2 = net.dup(ep, VFD_BASE).unwrap();
        assert_ne!(ep, ep2);
        assert_eq!(net.obj_of(ep), net.obj_of(ep2));
        assert_eq!(net.close(ep), Some(None));
        assert!(net.get(ep2).is_some());
        assert_eq!(net.close(ep2), Some(None));
        assert!(net.objs.is_empty());
    }

    #[test]
    fn client_events_and_hang_detection() {
        let mut net = Net::new(1);
        assert!(net.client_events().is_empty(), "no listener yet");
        let l = listener(&mut net);
        assert_eq!(net.client_events(), vec![ClientEvent::Connect]);
        let req = b"POST /x HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi".to_vec();
        let (c, _) = net.connect(req).unwrap();
        assert_eq!(net.client_events(), vec![ClientEvent::Send(0)]);
        net.deliver(c, usize::MAX);
        assert_eq!(net.client_events(), vec![ClientEvent::Close(0)]);
        assert!(net.hung_clients().is_empty(), "not accepted yet");
        net.accept(l, true).unwrap();
        assert!(net.hung_clients().is_empty(), "not read yet");
        net.clients[c].rx.clear();
        assert_eq!(net.hung_clients(), vec![0]);
        net.clients[c]
            .response
            .extend_from_slice(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
        assert!(net.hung_clients().is_empty());
        assert_eq!(http_status(&net.clients[c].response), Some(200));
    }

    #[test]
    fn eventfd_readiness_follows_the_counter() {
        let mut net = Net::new(0);
        let ev = net.create(
            Obj::EventFd {
                count: 0,
                nonblock: true,
            },
            VFD_BASE,
        );
        let ep = net.create(
            Obj::Epoll {
                interests: BTreeMap::new(),
            },
            VFD_BASE,
        );
        assert_eq!(net.ready(ev), EPOLLOUT);
        assert_eq!(
            net.epoll_ctl(ep, libc::EPOLL_CTL_ADD, ev, EPOLLIN | EPOLLET, 1),
            0
        );
        assert!(net.epoll_poll(ep, 16).is_empty());
        let obj = net.obj_of(ev).unwrap();
        match net.get_mut(ev) {
            Some(Obj::EventFd { count, .. }) => *count += 1,
            _ => unreachable!(),
        }
        net.signal(obj, EPOLLIN);
        assert_eq!(net.ready(ev), EPOLLIN | EPOLLOUT);
        assert_eq!(net.epoll_poll(ep, 16), vec![(EPOLLIN, 1)]);
        assert!(net.epoll_poll(ep, 16).is_empty(), "edge consumed");
        match net.get_mut(ev) {
            Some(Obj::EventFd { count, .. }) => *count = 0,
            _ => unreachable!(),
        }
        assert_eq!(net.ready(ev), EPOLLOUT);
        assert_eq!(net.epoll_ctl(ep, libc::EPOLL_CTL_MOD, ev, EPOLLIN, 2), 0);
        assert!(net.epoll_poll(ep, 16).is_empty(), "level, not readable");
    }

    #[test]
    fn connection_readiness_through_fin_and_shutdown() {
        let mut net = Net::new(1);
        let l = listener(&mut net);
        let (c, _) = net.connect(b"GET / HTTP/1.1\r\n\r\n".to_vec()).unwrap();
        let (s, _) = net.accept(l, false).unwrap();
        assert!(!net.nonblock(s));
        assert_eq!(net.ready(s), EPOLLOUT, "nothing to read yet");
        net.deliver(c, 3);
        assert_eq!(net.clients[c].rx.len(), 3);
        assert_eq!(net.ready(s), EPOLLIN | EPOLLOUT);
        net.clients[c].rx.clear();
        net.clients[c].fin = true;
        assert_eq!(
            net.ready(s),
            EPOLLIN | EPOLLOUT | EPOLLRDHUP,
            "EOF is readable"
        );
        match net.get_mut(s) {
            Some(Obj::Socket {
                state: SockState::Connected { shut_wr, .. },
                ..
            }) => *shut_wr = true,
            _ => unreachable!(),
        }
        assert_eq!(net.ready(s), EPOLLIN | EPOLLRDHUP | EPOLLHUP);
        assert_eq!(net.close(s), Some(Some(c)));
        assert_eq!(net.close(s), None, "EBADF on the second close");
        assert_eq!(net.ready(s), 0);
    }

    #[test]
    fn request_completeness() {
        assert!(http_request_complete(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(!http_request_complete(b"GET / HTTP/1.1\r\nHost: x\r\n"));
        assert!(!http_request_complete(
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabc"
        ));
        assert!(http_request_complete(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"
        ));
    }
}
