use std::cmp;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum NodeMinimum {
    Value(u32),
    EndOfArray,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct MergedIteratorItem {
    pub kind: usize,
    pub index: usize,
}

/// A merged iterator over multiple sorted arrays.
///
/// ### Implementation details
/// Internally, a tournament tree is formed to find the minimum of all candidates. Arrays that have
/// ended are treated as an infinitely large value (see `NodeMinimum`).
/// The conceptual "position" index may represent a tournament comparison or a leaf node (a sorted
/// array). There are `n - 1` comparisons, followed by `n` leaf nodes. The comparisons are stored in
/// `min`, while the currently read index of the leaf nodes is stored in `idx`.
/// This index scheme, inspired by binary heaps, has a cool property that allows it to easily mapped
/// to a binary tree: The parent of a node at position `i` is at position `i / 2`, and the childrens
/// are at positions `2 * i` and `2 * i + 1`.
pub struct MergedIterator<'a> {
    seqs: Vec<&'a [u32]>,
    min: Vec<(NodeMinimum, usize)>,
    idx: Vec<usize>,
}

impl<'a> MergedIterator<'a> {
    pub fn new(seqs: Vec<&'a [u32]>) -> Self {
        let min = vec![(NodeMinimum::EndOfArray, 0); seqs.len() - 1];
        let idx = vec![0; seqs.len()];
        let mut ret = MergedIterator { seqs, min, idx };

        ret.initialize_minimum(0);

        ret
    }

    fn node_value(&self, position: usize) -> (NodeMinimum, usize) {
        if position >= self.min.len() {
            let i = position - self.min.len();
            (
                match self.seqs[i].get(self.idx[i]) {
                    Some(x) => NodeMinimum::Value(*x),
                    None => NodeMinimum::EndOfArray,
                },
                i,
            )
        } else {
            self.min[position]
        }
    }

    fn initialize_minimum(&mut self, position: usize) -> (NodeMinimum, usize) {
        if position >= self.min.len() {
            self.node_value(position)
        } else {
            let left = self.initialize_minimum(position * 2 + 1);
            let right = self.initialize_minimum(position * 2 + 2);

            let min = cmp::min(left, right);
            self.min[position] = min;
            min
        }
    }

    fn update_minimum(&mut self, position: usize) {
        let left = self.node_value(position * 2 + 1);
        let right = self.node_value(position * 2 + 2);
        self.min[position] = cmp::min(left, right);

        if position != 0 {
            self.update_minimum((position - 1) / 2);
        }
    }
}

impl<'a> Iterator for MergedIterator<'a> {
    type Item = MergedIteratorItem;

    fn next(&mut self) -> Option<Self::Item> {
        match self.node_value(0) {
            (NodeMinimum::Value(_), kind) => {
                self.idx[kind] += 1;
                self.update_minimum((kind + self.min.len() - 1) / 2);
                Some(MergedIteratorItem {
                    kind,
                    index: self.idx[kind] - 1,
                })
            }
            (NodeMinimum::EndOfArray, _) => None,
        }
    }
}
