import tensorflow as tf

def load_batches(path, batch_size, nfeatures, nselect):
    batches = tf.data.experimental.make_csv_dataset(
        path,
        batch_size=batch_size,
        header=False,
        shuffle=True,
        column_names=[str(i) for i in range(nfeatures)],
        column_defaults=[tf.float32 for _ in range(nselect)],
        select_columns=[str(i) for i in range(nselect)],
        label_name='{0}'.format(nselect - 1),
    )
    return batches

def classification_mapper(features, label, xmin, xmax, eps=1e-10):
    features = (tf.stack(list(features.values()), axis=-1) - xmin) / (xmax - xmin + eps)
    label = tf.clip_by_value(label, 0, 1)
    return features, label

def exclude_feature_mapper(features, label, idx):
    return features * idx, label

def concat_batches(b1, b2):
    features1, labels1 = b1
    features2, labels2 = b2
    return ({feature: tf.concat([features1[feature], features2[feature]], axis=0) for feature in features1.keys()}, tf.concat([labels1, labels2], axis=0))
