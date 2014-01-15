#include <QDebug>
#include <QDir>
#include <QFile>
#include <QSslKey>

#include "KeyShare.hpp"
#include "DsaPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  KeyShare::KeyShare(const QString &path) :
    _fs_enabled(!path.isEmpty()),
    _path(path)
  {
    if(_fs_enabled) {
      CheckPath();
    }
  }

  QSharedPointer<AsymmetricKey> KeyShare::GetKey(const QString &name) const
  {
    if(_keys.contains(name)) {
      return _keys[name];
    } else if(_certs.contains(name)) {
        QSharedPointer<QSslCertificate> cert = _certs[name];
        QSslKey pubkey = cert->publicKey();
        QSharedPointer<AsymmetricKey> key(new DsaPublicKey(pubkey.toDer()));
        KeyShare *ks = const_cast<KeyShare *>(this);
        ks->_keys[name] = key;
        return key;
    } else if(_fs_enabled) {
      QString key_path = _path + "/" + name + ".pub";
      QFile key_file(key_path);
      if(key_file.exists()) {
        key_file.open(QIODevice::ReadOnly);
        QSharedPointer<QSslCertificate> cert(new QSslCertificate(&key_file, QSsl::Der));
        QSslKey pubkey = cert->publicKey();
        QSharedPointer<AsymmetricKey> key(new DsaPublicKey(pubkey.toDer()));
        KeyShare *ks = const_cast<KeyShare *>(this);
        ks->_certs[name] = cert;
        ks->_keys[name] = key;
        return key;
      }
    }

    return QSharedPointer<AsymmetricKey>();
  }

  QSharedPointer<QSslCertificate> KeyShare::GetCertificate(const QString &name) const
  {
    if(_certs.contains(name)) {
        return _certs[name];
    } else if(_fs_enabled) {
      QString key_path = _path + "/" + name + ".pub";
      QFile key_file(key_path);
      if(key_file.exists()) {
        key_file.open(QIODevice::ReadOnly);
        QSharedPointer<QSslCertificate> cert(new QSslCertificate(&key_file, QSsl::Der));
        QSslKey pubkey = cert->publicKey();
        QSharedPointer<AsymmetricKey> key(new DsaPublicKey(pubkey.toDer()));
        KeyShare *ks = const_cast<KeyShare *>(this);
        ks->_certs[name] = cert;
        ks->_keys[name] = key;
        return cert;
      }
    }

    return QSharedPointer<QSslCertificate>();
  }

  void KeyShare::AddKey(const QString &name, QSharedPointer<AsymmetricKey> key)
  {
    _keys[name] = key;

    QMutableLinkedListIterator<QString> iterator(_sorted_keys);
    while(iterator.hasNext()) {
      if(name < iterator.peekNext()) {
        break;
      }
      iterator.next();
    }
    iterator.insert(name);
  }

  void KeyShare::AddCertificate(const QString &name, QSharedPointer<QSslCertificate> cert)
  {
    _certs[name] = cert;
    QSslKey pubkey = cert->publicKey();
    QSharedPointer<AsymmetricKey> key(new DsaPublicKey(pubkey.toDer()));
    AddKey(name, key);
  } 

  bool KeyShare::Contains(const QString &name) const
  {
    if(_keys.contains(name)) {
      return true;
    } else if(_fs_enabled) {
      QString key_path = _path + "/" + name + ".pub";
      QFile key_file(key_path);
      return key_file.exists();
    }

    return false;
  }

  void KeyShare::CheckPath()
  {
    QDir key_path(_path, "*.pub");
    foreach(const QString &key_name, key_path.entryList()) {
      QString path = _path + "/" + key_name;
      QFile key_file(path);
      key_file.open(QIODevice::ReadOnly);
      QSharedPointer<QSslCertificate> cert(new QSslCertificate(&key_file, QSsl::Der));
      QSslKey pubkey = cert->publicKey();
      QSharedPointer<AsymmetricKey> key(new DsaPublicKey(pubkey.toDer()));
      if(!key->IsValid()) {
        qDebug() << "Invalid key:" << path;
        continue;
      }

      QString name = key_name.left(key_name.length() - 4);
      AddCertificate(name, cert);
    }
  }
}
}
