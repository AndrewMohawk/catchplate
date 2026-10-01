//! Request-level durable ordering and conservative recovery-capacity accounting.
//! This reducer never authenticates an authority result or proves cleanup.

struct Flight {
    request: Vec<u8>,
    start_cost: usize,
    started: bool,
}

pub(crate) struct State {
    maximum_records: usize,
    maximum_bytes: usize,
    records: usize,
    bytes: usize,
    loading: bool,
    failed: bool,
    has_starts: bool,
    flight: Option<Flight>,
}

impl State {
    pub(crate) fn new(maximum_records: usize, maximum_bytes: usize, head_bytes: usize) -> Self {
        Self { maximum_records, maximum_bytes, records: 0, bytes: head_bytes.max(4096),
            loading: true, failed: maximum_records == 0 || head_bytes.max(4096) > maximum_bytes,
            has_starts: false, flight: None }
    }

    fn refuse<T>(&mut self, message: &'static str) -> Result<T, &'static str> {
        self.failed = true;
        Err(message)
    }

    fn add_record(&mut self, bytes: usize) -> Result<(), &'static str> {
        let Some(next_bytes) = self.bytes.checked_add(bytes) else {
            return self.refuse("production replay byte accounting overflowed");
        };
        if self.records >= self.maximum_records || next_bytes > self.maximum_bytes {
            return self.refuse("production replay physical recovery capacity exhausted");
        }
        self.records += 1;
        self.bytes = next_bytes;
        Ok(())
    }

    pub(crate) fn recover_start(&mut self, request: &[u8], physical_bytes: usize) -> Result<(), &'static str> {
        if self.failed || !self.loading || self.flight.is_some() || request.is_empty() {
            return self.refuse("production replay start order differs");
        }
        self.add_record(physical_bytes)?;
        self.has_starts = true;
        self.flight = Some(Flight { request: request.to_vec(), start_cost: 0, started: true });
        Ok(())
    }

    pub(crate) fn recover_complete(&mut self, request: &[u8], physical_bytes: usize) -> Result<(), &'static str> {
        if self.failed || !self.loading || request.is_empty()
            || self.flight.as_ref().is_some_and(|flight| flight.request != request || !flight.started)
            || (self.has_starts && self.flight.is_none()) {
            return self.refuse("production replay completion has no matching exact start");
        }
        self.add_record(physical_bytes)?;
        self.flight = None;
        Ok(())
    }

    pub(crate) fn finish_recovery(&mut self) -> Result<(), &'static str> {
        if self.failed || !self.loading || self.flight.is_some() {
            return self.refuse("production replay contains an incomplete authority attempt");
        }
        self.loading = false;
        Ok(())
    }

    pub(crate) fn ready(&self) -> bool { !self.loading && !self.failed && self.flight.is_none() }

    pub(crate) fn next_sequence(&self) -> Result<u64, &'static str> {
        if !self.ready() { return Err("production replay is fenced"); }
        u64::try_from(self.records).ok().and_then(|value| value.checked_add(1))
            .ok_or("production replay sequence overflowed")
    }

    // The fixed journal schema has two base64 originals plus bounded metadata.
    // 3*(request+response)+4096 exceeds its serialized record plus decoded
    // originals. The separate initial reserve also covers the terminal head.
    fn cost(request: usize, response: usize) -> Option<usize> {
        request.checked_add(response)?.checked_mul(3)?.checked_add(4096)
    }

    pub(crate) fn begin(&mut self, request: &[u8], start_bytes: usize,
        maximum_response_bytes: usize) -> Result<u64, &'static str> {
        let sequence = match self.next_sequence() {
            Ok(sequence) => sequence,
            Err(message) => return self.refuse(message),
        };
        if request.is_empty() { return self.refuse("production replay request is empty"); }
        // Fence before the caller can perform any journal write or contact.
        self.failed = true;
        let start_cost = Self::cost(request.len(), start_bytes).ok_or("production replay start size overflowed")?;
        let completion_cost = Self::cost(request.len(), maximum_response_bytes)
            .ok_or("production replay completion size overflowed")?;
        if self.records.checked_add(2).is_none_or(|count| count > self.maximum_records)
            || self.bytes.checked_add(start_cost).and_then(|bytes| bytes.checked_add(completion_cost))
                .is_none_or(|bytes| bytes > self.maximum_bytes) {
            return Err("production replay cannot reserve both physical records");
        }
        self.flight = Some(Flight { request: request.to_vec(), start_cost, started: false });
        self.failed = false;
        Ok(sequence)
    }

    pub(crate) fn start_persisted(&mut self) -> Result<(), &'static str> {
        let Some(flight) = &self.flight else { return self.refuse("production replay start was not reserved"); };
        if self.failed || self.loading || flight.started {
            return self.refuse("production replay start readback order differs");
        }
        let cost = flight.start_cost;
        self.add_record(cost)?;
        self.flight.as_mut().expect("retained flight").started = true;
        self.has_starts = true;
        Ok(())
    }

    pub(crate) fn complete(&mut self, response_bytes: usize) -> Result<(), &'static str> {
        let Some(flight) = &self.flight else { return self.refuse("production replay completion has no attempt"); };
        if self.failed || self.loading || !flight.started || response_bytes == 0 {
            return self.refuse("production replay completion preceded durable start");
        }
        let Some(cost) = Self::cost(flight.request.len(), response_bytes) else {
            return self.refuse("production replay completion size overflowed");
        };
        self.add_record(cost)?;
        self.flight = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "production_replay_tests.rs"]
mod tests;
